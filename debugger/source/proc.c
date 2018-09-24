// golden
// 6/12/2018
//

#include "proc.h"

int proc_list_handle(int fd, struct cmd_packet *packet) {
    void *data;
    uint64_t num;
    uint32_t length;

    sys_proc_list(NULL, &num);

    if(num > 0) {
        length = sizeof(struct proc_list_entry) * num;
        data = pfmalloc(length);
        if(!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        sys_proc_list(data, &num);
        
        net_send_status(fd, CMD_SUCCESS);
        net_send_data(fd, &num, sizeof(uint32_t));
        net_send_data(fd, data, length);

        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    return 1;
}

int proc_read_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_read_packet *rp;
    void *data;
    uint64_t left;
    uint64_t address;

    rp = (struct cmd_proc_read_packet *)packet->data;

    if(rp) {
        // allocate a small buffer
        data = pfmalloc(NET_MAX_LENGTH);
        if(!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }
        
        net_send_status(fd, CMD_SUCCESS);

        left = rp->length;
        address = rp->address;

        // send by chunks
        while(left > 0) {
            memset(data, NULL, NET_MAX_LENGTH);

            if(left > NET_MAX_LENGTH) {
                sys_proc_rw(rp->pid, address, data, NET_MAX_LENGTH, 0);
                net_send_data(fd, data, NET_MAX_LENGTH);

                address += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            } else {
                sys_proc_rw(rp->pid, address, data, left, 0);
                net_send_data(fd, data, left);

                address += left;
                left -= left;
            }
        }

        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    
    return 1;
}

int proc_write_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_write_packet *wp;
    void *data;
    uint64_t left;
    uint64_t address;

    wp = (struct cmd_proc_write_packet *)packet->data;

    if(wp) {
        // only allocate a small buffer
        data = pfmalloc(NET_MAX_LENGTH);
        if(!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }
        
        net_send_status(fd, CMD_SUCCESS);
        
        left = wp->length;
        address = wp->address;

        // write in chunks
        while(left > 0) {
            if(left > NET_MAX_LENGTH) {
                net_recv_data(fd, data, NET_MAX_LENGTH, 1);
                sys_proc_rw(wp->pid, address, data, NET_MAX_LENGTH, 1);

                address += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            } else {
                net_recv_data(fd, data, left, 1);
                sys_proc_rw(wp->pid, address, data, left, 1);

                address += left;
                left -= left;
            }
        }

        net_send_status(fd, CMD_SUCCESS);

        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    
    return 1;
}

int proc_maps_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_maps_packet *mp;
    struct sys_proc_vm_map_args args;
    uint32_t size;
    uint32_t num;

    mp = (struct cmd_proc_maps_packet *)packet->data;

    if(mp) {
        memset(&args, NULL, sizeof(args));

        if(sys_proc_cmd(mp->pid, SYS_PROC_VM_MAP, &args)) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        size = args.num * sizeof(struct proc_vm_map_entry);

        args.maps = (struct proc_vm_map_entry *)pfmalloc(size);
        if(!args.maps) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        if(sys_proc_cmd(mp->pid, SYS_PROC_VM_MAP, &args)) {
            free(args.maps);
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        net_send_status(fd, CMD_SUCCESS);
        num = (uint32_t)args.num;
        net_send_data(fd, &num, sizeof(uint32_t));
        net_send_data(fd, args.maps, size);

        free(args.maps);

        return 0;
    }
    
    net_send_status(fd, CMD_ERROR);
    
    return 1;
}

int proc_install_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_install_packet *ip;
    struct sys_proc_install_args args;
    struct cmd_proc_install_response resp;

    ip = (struct cmd_proc_install_packet *)packet->data;

    if(!ip) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    args.stubentryaddr = NULL;
    sys_proc_cmd(ip->pid, SYS_PROC_INSTALL, &args);

    if(!args.stubentryaddr) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    resp.rpcstub = args.stubentryaddr;

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &resp, CMD_PROC_INSTALL_RESPONSE_SIZE);

    return 0;
}

int proc_call_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_call_packet *cp;
    struct sys_proc_call_args args;
    struct cmd_proc_call_response resp;

    cp = (struct cmd_proc_call_packet *)packet->data;

    if(!cp) {
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    // copy over the arguments for the call
    args.pid = cp->pid;
    args.rpcstub = cp->rpcstub;
    args.rax = NULL;
    args.rip = cp->rpc_rip;
    args.rdi = cp->rpc_rdi;
    args.rsi = cp->rpc_rsi;
    args.rdx = cp->rpc_rdx;
    args.rcx = cp->rpc_rcx;
    args.r8 = cp->rpc_r8;
    args.r9 = cp->rpc_r9;

    sys_proc_cmd(cp->pid, SYS_PROC_CALL, &args);

    resp.pid = cp->pid;
    resp.rpc_rax = args.rax;

    net_send_status(fd, CMD_SUCCESS);
    net_send_data(fd, &resp, CMD_PROC_CALL_RESPONSE_SIZE);

    return 0;
}

int proc_elf_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_elf_packet *ep;
    struct sys_proc_elf_args args;
    void *elf;
    
    ep = (struct cmd_proc_elf_packet *)packet->data;

    if(ep) {
        elf = pfmalloc(ep->length);
        if(!elf) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        net_send_status(fd, CMD_SUCCESS);

        net_recv_data(fd, elf, ep->length, 1);

        args.elf = elf;

        if(sys_proc_cmd(ep->pid, SYS_PROC_ELF, &args)) {
            free(elf);
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        free(elf);

        net_send_status(fd, CMD_SUCCESS);

        return 0;
    }

    net_send_status(fd, CMD_ERROR);
    
    return 1;
}

int proc_protect_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_protect_packet *pp;
    struct sys_proc_protect_args args;

    pp = (struct cmd_proc_protect_packet *)packet->data;

    if(pp) {
        args.address = pp->address;
        args.length = pp->length;
        args.prot = pp->newprot;
        sys_proc_cmd(pp->pid, SYS_PROC_PROTECT, &args);
        
        net_send_status(fd, CMD_SUCCESS);
    }
    
    net_send_status(fd, CMD_DATA_NULL);

    return 0;
}

size_t proc_scan_getSizeOfValueType(cmd_proc_scan_valuetype valType) {
    switch (valType) {
       case valTypeUInt8:
       case valTypeInt8:
          return 1;
       case valTypeUInt16:
       case valTypeInt16:
          return 2;
       case valTypeUInt32:
       case valTypeInt32:
       case valTypeFloat:
          return 4;
       case valTypeUInt64:
       case valTypeInt64:
       case valTypeDouble:
          return 8;
       case valTypeArrBytes:
       case valTypeString:
       default:
          return NULL;
    }
}

bool proc_scan_compareValues(cmd_proc_scan_comparetype cmpType, cmd_proc_scan_valuetype valType, size_t valTypeLength,
                                 unsigned char *pScanValue, unsigned char *pMemoryValue, unsigned char *pExtraValue) {
    switch (cmpType) {
       case cmpTypeExactValue:
       {
          bool isFound = false;
          for (size_t j = 0; j < valTypeLength - 1; j++) {
             isFound = (pScanValue[j] == pMemoryValue[j]);
             if (!isFound)
                break;
          }
          return isFound;
       }
       case cmpTypeFuzzyValue:
       {
          if (valType == valTypeFloat) {
             float diff = *(float *)pScanValue - *(float *)pMemoryValue;
             return diff < 1.0f && diff > -1.0f;
          }
          else if (valType == valTypeDouble) {
             double diff = *(double *)pScanValue - *(double *)pMemoryValue;
             return diff < 1.0 && diff > -1.0;
          }
          else {
             return false;
          }
       }
       case cmpTypeBiggerThan:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue > *pScanValue;
             case valTypeInt8:
                return *(int8_t *)pMemoryValue > *(int8_t *)pScanValue;
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue > *(uint16_t *)pScanValue;
             case valTypeInt16:
                return *(int16_t *)pMemoryValue > *(int16_t *)pScanValue;
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue > *(uint32_t *)pScanValue;
             case valTypeInt32:
                return *(int32_t *)pMemoryValue > *(int32_t *)pScanValue;
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue > *(uint64_t *)pScanValue;
             case valTypeInt64:
                return *(int64_t *)pMemoryValue > *(int64_t *)pScanValue;
             case valTypeFloat:
                return *(float *)pMemoryValue > *(float *)pScanValue;
             case valTypeDouble:
                return *(double *)pMemoryValue > *(double *)pScanValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeSmallerThan:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue < *pScanValue;
             case valTypeInt8:
                return *(int8_t *)pMemoryValue < *(int8_t *)pScanValue;
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue < *(uint16_t *)pScanValue;
             case valTypeInt16:
                return *(int16_t *)pMemoryValue < *(int16_t *)pScanValue;
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue < *(uint32_t *)pScanValue;
             case valTypeInt32:
                return *(int32_t *)pMemoryValue < *(int32_t *)pScanValue;
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue < *(uint64_t *)pScanValue;
             case valTypeInt64:
                return *(int64_t *)pMemoryValue < *(int64_t *)pScanValue;
             case valTypeFloat:
                return *(float *)pMemoryValue < *(float *)pScanValue;
             case valTypeDouble:
                return *(double *)pMemoryValue < *(double *)pScanValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeValueBetween:
       {
          switch (valType) {
             case valTypeUInt8:
                if (*pExtraValue > *pScanValue)
                   return *pMemoryValue > *pScanValue && *pMemoryValue < *pExtraValue;
                return *pMemoryValue < *pScanValue && *pMemoryValue > *pExtraValue;
             case valTypeInt8:
                if (*(int8_t *)pExtraValue > *(int8_t *)pScanValue)
                   return *(int8_t *)pMemoryValue > *(int8_t *)pScanValue && *(int8_t *)pMemoryValue < *(int8_t*)pExtraValue;
                return *(int8_t *)pMemoryValue < *(int8_t *)pScanValue && *(int8_t *)pMemoryValue > *(int8_t *)pExtraValue;
             case valTypeUInt16:
                if (*(uint16_t *)pExtraValue > *(uint16_t *)pScanValue)
                   return *(uint16_t *)pMemoryValue > *(uint16_t *)pScanValue && *(uint16_t *)pMemoryValue < *(uint16_t*)pExtraValue;
                return *(uint16_t *)pMemoryValue < *(uint16_t *)pScanValue && *(uint16_t *)pMemoryValue > *(uint16_t *)pExtraValue;
             case valTypeInt16:
                if (*(int16_t *)pExtraValue > *(int16_t *)pScanValue)
                   return *(int16_t *)pMemoryValue > *(int16_t *)pScanValue && *(int16_t *)pMemoryValue < *(int16_t*)pExtraValue;
                return *(int16_t *)pMemoryValue < *(int16_t *)pScanValue && *(int16_t *)pMemoryValue > *(int16_t *)pExtraValue;
             case valTypeUInt32:
                if (*(uint32_t *)pExtraValue > *(uint32_t *)pScanValue)
                   return *(uint32_t *)pMemoryValue > *(uint32_t *)pScanValue && *(uint32_t *)pMemoryValue < *(uint32_t*)pExtraValue;
                return *(uint32_t *)pMemoryValue < *(uint32_t *)pScanValue && *(uint32_t *)pMemoryValue > *(uint32_t *)pExtraValue;
             case valTypeInt32:
                if (*(int32_t *)pExtraValue > *(int32_t *)pScanValue)
                   return *(int32_t *)pMemoryValue > *(int32_t *)pScanValue && *(int32_t *)pMemoryValue < *(int32_t*)pExtraValue;
                return *(int32_t *)pMemoryValue < *(int32_t *)pScanValue && *(int32_t *)pMemoryValue > *(int32_t *)pExtraValue;
             case valTypeUInt64:
                if (*(uint64_t *)pExtraValue > *(uint64_t *)pScanValue)
                   return *(uint64_t *)pMemoryValue > *(uint64_t *)pScanValue && *(uint64_t *)pMemoryValue < *(uint64_t*)pExtraValue;
                return *(uint64_t *)pMemoryValue < *(uint64_t *)pScanValue && *(uint64_t *)pMemoryValue > *(uint64_t *)pExtraValue;
             case valTypeInt64:
                if (*(int64_t *)pExtraValue > *(int64_t *)pScanValue)
                   return *(int64_t *)pMemoryValue > *(int64_t *)pScanValue && *(int64_t *)pMemoryValue < *(int64_t*)pExtraValue;
                return *(int64_t *)pMemoryValue < *(int64_t *)pScanValue && *(int64_t *)pMemoryValue > *(int64_t *)pExtraValue;
             case valTypeFloat:
                if (*(float *)pExtraValue > *(float *)pScanValue)
                   return *(float *)pMemoryValue > *(float *)pScanValue && *(float *)pMemoryValue < *(float*)pExtraValue;
                return *(float *)pMemoryValue < *(float *)pScanValue && *(float *)pMemoryValue > *(float *)pExtraValue;
             case valTypeDouble:
                if (*(double *)pExtraValue > *(double *)pScanValue)
                   return *(double *)pMemoryValue > *(double *)pScanValue && *(double *)pMemoryValue < *(double*)pExtraValue;
                return *(double *)pMemoryValue < *(double *)pScanValue && *(double *)pMemoryValue > *(double *)pExtraValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeIncreasedValue:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue > *pExtraValue;
             case valTypeInt8:
                return *(int8_t *)pMemoryValue > *(int8_t *)pExtraValue;
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue > *(uint16_t *)pExtraValue;
             case valTypeInt16:
                return *(int16_t *)pMemoryValue > *(int16_t *)pExtraValue;
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue > *(uint32_t *)pExtraValue;
             case valTypeInt32:
                return *(int32_t *)pMemoryValue > *(int32_t *)pExtraValue;
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue > *(uint64_t *)pExtraValue;
             case valTypeInt64:
                return *(int64_t *)pMemoryValue > *(int64_t *)pExtraValue;
             case valTypeFloat:
                return *(float *)pMemoryValue > *(float *)pExtraValue;
             case valTypeDouble:
                return *(double *)pMemoryValue > *(double *)pExtraValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeIncreasedValueBy:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue == (*pExtraValue + *pScanValue);
             case valTypeInt8:
                return *(int8_t *)pMemoryValue == (*(int8_t *)pExtraValue + *(int8_t *)pScanValue);
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue == (*(uint16_t *)pExtraValue + *(uint16_t *)pScanValue);
             case valTypeInt16:
                return *(int16_t *)pMemoryValue == (*(int16_t *)pExtraValue + *(int16_t *)pScanValue);
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue == (*(uint32_t *)pExtraValue + *(uint32_t *)pScanValue);
             case valTypeInt32:
                return *(int32_t *)pMemoryValue == (*(int32_t *)pExtraValue + *(int32_t *)pScanValue);
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue == (*(uint64_t *)pExtraValue + *(uint64_t *)pScanValue);
             case valTypeInt64:
                return *(int64_t *)pMemoryValue == (*(int64_t *)pExtraValue + *(int64_t *)pScanValue);
             case valTypeFloat:
                return *(float *)pMemoryValue == (*(float *)pExtraValue + *(float *)pScanValue);
             case valTypeDouble:
                return *(double *)pMemoryValue == (*(double *)pExtraValue + *(float *)pScanValue);
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeDecreasedValue:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue < *pExtraValue;
             case valTypeInt8:
                return *(int8_t *)pMemoryValue < *(int8_t *)pExtraValue;
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue < *(uint16_t *)pExtraValue;
             case valTypeInt16:
                return *(int16_t *)pMemoryValue < *(int16_t *)pExtraValue;
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue < *(uint32_t *)pExtraValue;
             case valTypeInt32:
                return *(int32_t *)pMemoryValue < *(int32_t *)pExtraValue;
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue < *(uint64_t *)pExtraValue;
             case valTypeInt64:
                return *(int64_t *)pMemoryValue < *(int64_t *)pExtraValue;
             case valTypeFloat:
                return *(float *)pMemoryValue < *(float *)pExtraValue;
             case valTypeDouble:
                return *(double *)pMemoryValue < *(double *)pExtraValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeDecreasedValueBy:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue == (*pExtraValue - *pScanValue);
             case valTypeInt8:
                return *(int8_t *)pMemoryValue == (*(int8_t *)pExtraValue - *(int8_t *)pScanValue);
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue == (*(uint16_t *)pExtraValue - *(uint16_t *)pScanValue);
             case valTypeInt16:
                return *(int16_t *)pMemoryValue == (*(int16_t *)pExtraValue - *(int16_t *)pScanValue);
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue == (*(uint32_t *)pExtraValue - *(uint32_t *)pScanValue);
             case valTypeInt32:
                return *(int32_t *)pMemoryValue == (*(int32_t *)pExtraValue - *(int32_t *)pScanValue);
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue == (*(uint64_t *)pExtraValue - *(uint64_t *)pScanValue);
             case valTypeInt64:
                return *(int64_t *)pMemoryValue == (*(int64_t *)pExtraValue - *(int64_t *)pScanValue);
             case valTypeFloat:
                return *(float *)pMemoryValue == (*(float *)pExtraValue - *(float *)pScanValue);
             case valTypeDouble:
                return *(double *)pMemoryValue == (*(double *)pExtraValue - *(float *)pScanValue);
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeChangedValue:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue != *pExtraValue;
             case valTypeInt8:
                return *(int8_t *)pMemoryValue != *(int8_t *)pExtraValue;
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue != *(uint16_t *)pExtraValue;
             case valTypeInt16:
                return *(int16_t *)pMemoryValue != *(int16_t *)pExtraValue;
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue != *(uint32_t *)pExtraValue;
             case valTypeInt32:
                return *(int32_t *)pMemoryValue != *(int32_t *)pExtraValue;
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue != *(uint64_t *)pExtraValue;
             case valTypeInt64:
                return *(int64_t *)pMemoryValue != *(int64_t *)pExtraValue;
             case valTypeFloat:
                return *(float *)pMemoryValue != *(float *)pExtraValue;
             case valTypeDouble:
                return *(double *)pMemoryValue != *(double *)pExtraValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeUnchangedValue:
       {
          switch (valType) {
             case valTypeUInt8:
                return *pMemoryValue == *pExtraValue;
             case valTypeInt8:
                return *(int8_t *)pMemoryValue == *(int8_t *)pExtraValue;
             case valTypeUInt16:
                return *(uint16_t *)pMemoryValue == *(uint16_t *)pExtraValue;
             case valTypeInt16:
                return *(int16_t *)pMemoryValue == *(int16_t *)pExtraValue;
             case valTypeUInt32:
                return *(uint32_t *)pMemoryValue == *(uint32_t *)pExtraValue;
             case valTypeInt32:
                return *(int32_t *)pMemoryValue == *(int32_t *)pExtraValue;
             case valTypeUInt64:
                return *(uint64_t *)pMemoryValue == *(uint64_t *)pExtraValue;
             case valTypeInt64:
                return *(int64_t *)pMemoryValue == *(int64_t *)pExtraValue;
             case valTypeFloat:
                return *(float *)pMemoryValue == *(float *)pExtraValue;
             case valTypeDouble:
                return *(double *)pMemoryValue == *(double *)pExtraValue;
             case valTypeArrBytes:
             case valTypeString:
                return false;
          }
       }
       case cmpTypeUnknownInitialValue:
       {
          return true;
       }
    }
    return false;
}

int proc_scan_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_scan_packet *sp = (struct cmd_proc_scan_packet *)packet->data;

    if(!sp) {
        net_send_status(fd, CMD_DATA_NULL);
       return 1;
    }

    // get and set data
    size_t valueLength = proc_scan_getSizeOfValueType(sp->valueType);
    if (!valueLength) {
       valueLength = sp->lenData;
    }

    unsigned char *data = (unsigned char *)pfmalloc(sp->lenData);
    if (!data) {
       net_send_status(fd, CMD_DATA_NULL);
       return 1;
    }
    
    net_send_status(fd, CMD_SUCCESS);

    net_recv_data(fd, data, sp->lenData, 1);

    // query for the process id
    struct sys_proc_vm_map_args args;
    memset(&args, NULL, sizeof(struct sys_proc_vm_map_args));
    if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
        free(data);
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    size_t size = args.num * sizeof(struct proc_vm_map_entry);
    args.maps = (struct proc_vm_map_entry *)pfmalloc(size);
    if (!args.maps) {
        free(data);
        net_send_status(fd, CMD_DATA_NULL);
        return 1;
    }

    if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
        free(args.maps);
        free(data);
        net_send_status(fd, CMD_ERROR);
        return 1;
    }

    net_send_status(fd, CMD_SUCCESS);

    uprintf("scan start");

    unsigned char *pExtraValue = valueLength == sp->lenData ? NULL : &data[valueLength];
    unsigned char *scanBuffer = (unsigned char *)pfmalloc(PAGE_SIZE);
    for (size_t i = 0; i < args.num; i++) {
       if ((args.maps[i].prot & PROT_READ) != PROT_READ) {
            continue;
       }

       uint64_t sectionStartAddr = args.maps[i].start;
       size_t sectionLen = args.maps[i].end - sectionStartAddr;

       // scan
       for (uint64_t j = 0; j < sectionLen; j += valueLength) {
            if(j == 0 || !(j % PAGE_SIZE)) {
                sys_proc_rw(sp->pid, sectionStartAddr, scanBuffer, PAGE_SIZE, 0);
            }

            uint64_t scanOffset = j % PAGE_SIZE;
            uint64_t curAddress = sectionStartAddr + j;
            if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, data, scanBuffer + scanOffset, pExtraValue)) {
                net_send_data(fd, &curAddress, sizeof(uint64_t));
            }
       }
    }

    uprintf("scan done");

    uint64_t endflag = 0xFFFFFFFFFFFFFFFF;
    net_send_data(fd, &endflag, sizeof(uint64_t));

    free(scanBuffer);
    free(args.maps);
    free(data);

    return 0;
}

int proc_info_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_info_packet *ip;
    struct sys_proc_info_args args;
    struct cmd_proc_info_response resp;

    ip = (struct cmd_proc_info_packet *)packet->data;

    if(ip) {
        sys_proc_cmd(ip->pid, SYS_PROC_INFO, &args);

        resp.pid = args.pid;
        memcpy(resp.name, args.name, sizeof(resp.name));
        memcpy(resp.path, args.path, sizeof(resp.path));
        memcpy(resp.titleid, args.titleid, sizeof(resp.titleid));
        memcpy(resp.contentid, args.contentid, sizeof(resp.contentid));

        net_send_status(fd, CMD_SUCCESS);
        net_send_data(fd, &resp, CMD_PROC_INFO_RESPONSE_SIZE);
        return 0;
    }
    
    net_send_status(fd, CMD_DATA_NULL);

    return 0;
}

int proc_alloc_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_alloc_packet *ap;
    struct sys_proc_alloc_args args;
    struct cmd_proc_alloc_response resp;

    ap = (struct cmd_proc_alloc_packet *)packet->data;

    if(ap) {
        args.length = ap->length;
        sys_proc_cmd(ap->pid, SYS_PROC_ALLOC, &args);

        resp.address = args.address;

        net_send_status(fd, CMD_SUCCESS);
        net_send_data(fd, &resp, CMD_PROC_ALLOC_RESPONSE_SIZE);
        return 0;
    }
    
    net_send_status(fd, CMD_DATA_NULL);

    return 0;
}

int proc_free_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_free_packet *fp;
    struct sys_proc_free_args args;

    fp = (struct cmd_proc_free_packet *)packet->data;

    if(fp) {
        args.address = fp->address;
        args.length = fp->length;
        sys_proc_cmd(fp->pid, SYS_PROC_FREE, &args);

        net_send_status(fd, CMD_SUCCESS);
        return 0;
    }
    
    net_send_status(fd, CMD_DATA_NULL);

    return 0;
}

int proc_handle(int fd, struct cmd_packet *packet) {
    switch(packet->cmd) {
        case CMD_PROC_LIST:
            return proc_list_handle(fd, packet);
        case CMD_PROC_READ:
            return proc_read_handle(fd, packet);
        case CMD_PROC_WRITE:
            return proc_write_handle(fd, packet);
        case CMD_PROC_MAPS:
            return proc_maps_handle(fd, packet);
        case CMD_PROC_INTALL:
            return proc_install_handle(fd, packet);
        case CMD_PROC_CALL:
            return proc_call_handle(fd, packet);
        case CMD_PROC_ELF:
            return proc_elf_handle(fd, packet);
        case CMD_PROC_PROTECT:
            return proc_protect_handle(fd, packet);
        case CMD_PROC_SCAN:
            return proc_scan_handle(fd, packet);
        case CMD_PROC_INFO:
            return proc_info_handle(fd, packet);
        case CMD_PROC_ALLOC:
            return proc_alloc_handle(fd, packet);
        case CMD_PROC_FREE:
            return proc_free_handle(fd, packet);
    }

    return 1;
}

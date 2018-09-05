// golden
// 6/12/2018
//

#include "proc.h"
#include <stdbool.h>

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
    uint64_t offset;

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
        offset = rp->address;

        // send by chunks
        while(left > 0) {
            memset(data, NULL, NET_MAX_LENGTH);

            if(left > NET_MAX_LENGTH) {
                sys_proc_rw(rp->pid, offset, data, NET_MAX_LENGTH, 0);
                net_send_data(fd, data, NET_MAX_LENGTH);

                offset += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            } else {
                sys_proc_rw(rp->pid, offset, data, left, 0);
                net_send_data(fd, data, left);

                offset += left;
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
    uint64_t offset;

    wp = (struct cmd_proc_write_packet *)packet->data;

    if(wp) {
        // only allocate a small buffer
        data = pfmalloc(NET_MAX_LENGTH);
        if(!data) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        left = wp->length;
        offset = wp->address;

        // write in chunks
        while(left > 0) {
            if(left > NET_MAX_LENGTH) {
                net_recv_data(fd, data, NET_MAX_LENGTH, 1);
                sys_proc_rw(wp->pid, offset, data, NET_MAX_LENGTH, 1);

                offset += NET_MAX_LENGTH;
                left -= NET_MAX_LENGTH;
            } else {
                net_recv_data(fd, data, left, 1);
                sys_proc_rw(wp->pid, offset, data, left, 1);

                offset += left;
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

int proc_info_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_info_packet *ip;
    struct sys_proc_vm_map_args args;
    uint32_t size;
    uint32_t num;

    ip = (struct cmd_proc_info_packet *)packet->data;

    if(ip) {
        memset(&args, NULL, sizeof(args));

        if(sys_proc_cmd(ip->pid, SYS_PROC_VM_MAP, &args)) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        size = args.num * sizeof(struct proc_vm_map_entry);

        args.maps = (struct proc_vm_map_entry *)pfmalloc(size);
        if(!args.maps) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        if(sys_proc_cmd(ip->pid, SYS_PROC_VM_MAP, &args)) {
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
    __asm("int 3");
    return 0;
}

int proc_call_handle(int fd, struct cmd_packet *packet) {
    __asm("int 3");
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
        sys_proc_cmd(pp->pid,SYS_PROC_PROTECT, &args);
        
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

typedef struct ResultNode {
    struct ResultNode* next;
    uint64_t address;
} ResultNode;
void resultlist_add(ResultNode** head, uint64_t address) {
    ResultNode* node = (ResultNode *)pfmalloc(sizeof(ResultNode));
	 node->address = address;
	 if (!(*head)) {
	 	node->next = NULL;
	 	*head = node;
	 } else {
	 	node->next = *head;
	 	*head = node;
	 }
}

int proc_scan_handle(int fd, struct cmd_packet *packet) {
    cmd_proc_scan_packet *sp = (cmd_proc_scan_packet *)packet->data;
    // get and set data
    size_t valueLength = proc_scan_getSizeOfValueType(sp->valueType);
    if (!valueLength)
       valueLength = sp->lenData;
    unsigned char *data = (unsigned char *)pfmalloc(sp->lenData);
    if (!data) {
       net_send_status(fd, CMD_DATA_NULL);
       return 1;
    }
    net_recv_data(fd, data, sp->lenData, 1);

    // query for the process id
    struct sys_proc_vm_map_args args = {0};
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
 
    ResultNode* list = NULL;
    size_t listItemCount = 0;
    unsigned char *pExtraValue = valueLength == sp->lenData ? NULL : &data[valueLength];
    for (size_t i = 0; i < args.num - 1; i++) {
       if ((args.maps[i].prot & PROT_READ) != PROT_READ)
         continue;

       uint64_t sectionStartAddr = args.maps[i].start;
       size_t sectionLen = args.maps[i].end - sectionStartAddr;
       // read
       unsigned char *scanBuffer = (unsigned char *)pfmalloc(sectionLen); // cast to uchar so we can byte shift
       sys_proc_rw(sp->pid, sectionStartAddr, scanBuffer, sectionLen, 0);
       // scan
       for (uint64_t i = 0; i < sectionLen; i += valueLength) {
          uint64_t curAddress = sectionStartAddr + i;
          if (proc_scan_compareValues(sp->compareType, sp->valueType, valueLength, data, scanBuffer + i, pExtraValue)) {
             resultlist_add(&list, curAddress);
             listItemCount++;
          }
       }
       free(scanBuffer);
    }
    free(args.maps);
    free(data);

    // sent data size
    uint32_t resultSize = listItemCount * sizeof(uint64_t);
    net_send_data(fd, &resultSize, sizeof(uint32_t));
    // send data
    while (list) {
       net_send_data(fd, &list->address, sizeof(uint64_t));
       ResultNode *_list = list;
       list = list->next;
       free(_list);
    }

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
        case CMD_PROC_INFO:
            return proc_info_handle(fd, packet);
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
    }

    return 1;
}

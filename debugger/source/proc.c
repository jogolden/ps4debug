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
        data = malloc(length);
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
        data = malloc(NET_MAX_LENGTH);
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
        data = malloc(NET_MAX_LENGTH);
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

        // I will use mmap because malloc is giving a kernel panic because it isnt allocating correctly?
        // fuck you sony!
        /*args.maps = (struct proc_vm_map_entry *)malloc(size);
        if(!args.maps) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }*/
        args.maps = (struct proc_vm_map_entry *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, NULL);
        if(!args.maps) {
            net_send_status(fd, CMD_DATA_NULL);
            return 1;
        }

        // prefault memory, wont work without this - thanks cturt...
        for(uint64_t i = 0; i < size; i++) {
            volatile uint8_t c;
            (void)c;
            
            c = ((char *)args.maps)[i];
        }

        uprintf("address: %llX size: %X", args.maps, size);

        if(sys_proc_cmd(ip->pid, SYS_PROC_VM_MAP, &args)) {
            net_send_status(fd, CMD_ERROR);
            return 1;
        }

        net_send_status(fd, CMD_SUCCESS);
        num = (uint32_t)args.num;
        net_send_data(fd, &num, sizeof(uint32_t));
        net_send_data(fd, args.maps, size);
        
        munmap(args.maps, size);
        //free(args.maps);

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
        elf = malloc(ep->length);
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
    __asm("int 3");
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
    }

    return 1;
}

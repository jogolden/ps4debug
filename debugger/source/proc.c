// golden
// 6/12/2018
//

#include "proc.h"

int proc_list_handle(int fd, struct cmd_packet *packet) {
    void *data;
    uint64_t num;
    uint32_t length;

    sys_proc_list(NULL, &num);

    if(num) {
        length = sizeof(struct proc_list_entry) * num;
        data = malloc(length);
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

    rp = (struct cmd_proc_read_packet *)packet->data;

    if(rp) {
        data = malloc(rp->length);
        sys_proc_rw(rp->pid, rp->address, data, rp->length, 0);
        net_send_status(fd, CMD_SUCCESS);
        net_send_data(fd, data, rp->length);
        free(data);

        return 0;
    }

    net_send_status(fd, CMD_DATA_NULL);
    
    return 1;
}

int proc_write_handle(int fd, struct cmd_packet *packet) {
    struct cmd_proc_write_packet *wp;
    void *data;

    wp = (struct cmd_proc_write_packet *)packet->data;

    if(wp) {
        data = malloc(wp->length);
        net_recv_data(fd, data, wp->length, 1);
        sys_proc_rw(wp->pid, wp->address, data, wp->length, 1);
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
        memset(&args, 0, sizeof(args));

        sys_proc_cmd(ip->pid, SYS_PROC_VM_MAP, &args);

        size = args.num * sizeof(struct proc_vm_map_entry);
        args.maps = (struct proc_vm_map_entry *)malloc(size);

        sys_proc_cmd(ip->pid, SYS_PROC_VM_MAP, &args);

        net_send_status(fd, CMD_SUCCESS);
        num = (uint32_t)args.num;
        net_send_data(fd, &num, sizeof(uint32_t));
        net_send_data(fd, args.maps, size);

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
        case CMD_PROC_PROTECT:
            return proc_protect_handle(fd, packet);
    }

    return 1;
}

// golden
// 6/12/2018
//

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <ps4.h>
#include "errno.h"
#include "kdbg.h"

#define PACKET_VERSION          "1.2"
#define PACKET_MAGIC            0xFFAABBCC

#define CMD_VERSION             0xBD000001

#define CMD_PROC_LIST           0xBDAA0001
#define CMD_PROC_READ           0xBDAA0002
#define CMD_PROC_WRITE          0xBDAA0003
#define CMD_PROC_MAPS           0xBDAA0004
#define CMD_PROC_INTALL         0xBDAA0005
#define CMD_PROC_CALL           0xBDAA0006
#define CMD_PROC_ELF            0xBDAA0007
#define CMD_PROC_PROTECT        0xBDAA0008
#define CMD_PROC_SCAN           0xBDAA0009
#define CMD_PROC_INFO           0xBDAA000A
#define CMD_PROC_ALLOC          0xBDAA000B
#define CMD_PROC_FREE           0xBDAA000C

#define CMD_DEBUG_ATTACH        0xBDBB0001
#define CMD_DEBUG_DETACH        0xBDBB0002
#define CMD_DEBUG_BREAKPT       0xBDBB0003
#define CMD_DEBUG_WATCHPT       0xBDBB0004
#define CMD_DEBUG_THREADS       0xBDBB0005
#define CMD_DEBUG_STOPTHR       0xBDBB0006
#define CMD_DEBUG_RESUMETHR     0xBDBB0007
#define CMD_DEBUG_GETREGS       0xBDBB0008
#define CMD_DEBUG_SETREGS       0xBDBB0009
#define CMD_DEBUG_GETFPREGS     0xBDBB000A
#define CMD_DEBUG_SETFPREGS     0xBDBB000B
#define CMD_DEBUG_GETDBGREGS    0xBDBB000C
#define CMD_DEBUG_SETDBGREGS    0xBDBB000D
#define CMD_DEBUG_STOPGO        0xBDBB0010
#define CMD_DEBUG_THRINFO       0xBDBB0011
#define CMD_DEBUG_SINGLESTEP    0xBDBB0012

#define CMD_KERN_BASE           0xBDCC0001
#define CMD_KERN_READ           0xBDCC0002
#define CMD_KERN_WRITE          0xBDCC0003

#define CMD_CONSOLE_REBOOT      0xBDDD0001
#define CMD_CONSOLE_END         0xBDDD0002
#define CMD_CONSOLE_PRINT       0xBDDD0003
#define CMD_CONSOLE_NOTIFY      0xBDDD0004
#define CMD_CONSOLE_INFO        0xBDDD0005

#define VALID_CMD(cmd)          (((cmd & 0xFF000000) >> 24) == 0xBD)
#define VALID_PROC_CMD(cmd)     (((cmd & 0x00FF0000) >> 16) == 0xAA)
#define VALID_DEBUG_CMD(cmd)    (((cmd & 0x00FF0000) >> 16) == 0xBB)
#define VALID_KERN_CMD(cmd)     (((cmd & 0x00FF0000) >> 16) == 0xCC)
#define VALID_CONSOLE_CMD(cmd)  (((cmd & 0x00FF0000) >> 16) == 0xDD)

#define CMD_SUCCESS              0x80000000
#define CMD_ERROR                0xF0000001
#define CMD_TOO_MUCH_DATA        0xF0000002
#define CMD_DATA_NULL            0xF0000003
#define CMD_ALREADY_DEBUG        0xF0000004
#define CMD_INVALID_INDEX        0xF0000005

#define CMD_FATAL_STATUS(s) ((s >> 28) == 15)

struct cmd_packet {
    uint32_t magic;
    uint32_t cmd;
    uint32_t datalen;
    // (field not actually part of packet, comes after)
    void *data;
} __attribute__((packed));
#define CMD_PACKET_SIZE 12

// proc
struct cmd_proc_read_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_PROC_READ_PACKET_SIZE 16

struct cmd_proc_write_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_PROC_WRITE_PACKET_SIZE 16

struct cmd_proc_maps_packet {
    uint32_t pid;
} __attribute__((packed));
#define CMD_PROC_MAPS_PACKET_SIZE 4

struct cmd_proc_install_packet {
    uint32_t pid;
} __attribute__((packed));
struct cmd_proc_install_response {
    uint64_t rpcstub;
} __attribute__((packed));
#define CMD_PROC_INSTALL_PACKET_SIZE 4
#define CMD_PROC_INSTALL_RESPONSE_SIZE 8

struct cmd_proc_call_packet {
    uint32_t pid;
    uint64_t rpcstub;
    uint64_t rpc_rip;
    uint64_t rpc_rdi;
    uint64_t rpc_rsi;
    uint64_t rpc_rdx;
    uint64_t rpc_rcx;
    uint64_t rpc_r8;
    uint64_t rpc_r9;
} __attribute__((packed));
struct cmd_proc_call_response {
    uint32_t pid;
    uint64_t rpc_rax;
} __attribute__((packed));
#define CMD_PROC_CALL_PACKET_SIZE 68
#define CMD_PROC_CALL_RESPONSE_SIZE 12

struct cmd_proc_elf_packet {
    uint32_t pid;
    uint32_t length;
} __attribute__((packed));
#define CMD_PROC_ELF_PACKET_SIZE 8

struct cmd_proc_protect_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
    uint32_t newprot;
} __attribute__((packed));
#define CMD_PROC_PROTECT_PACKET_SIZE 20

typedef enum cmd_proc_scan_valuetype {
   valTypeUInt8 = 0,
   valTypeInt8,
   valTypeUInt16,
   valTypeInt16,
   valTypeUInt32,
   valTypeInt32,
   valTypeUInt64,
   valTypeInt64,
   valTypeFloat,
   valTypeDouble,
   valTypeArrBytes,
   valTypeString
} __attribute__((__packed__)) cmd_proc_scan_valuetype;

typedef enum cmd_proc_scan_comparetype {
   cmpTypeExactValue = 0,
   cmpTypeFuzzyValue,
   cmpTypeBiggerThan,
   cmpTypeSmallerThan,
   cmpTypeValueBetween,
   cmpTypeIncreasedValue,
   cmpTypeIncreasedValueBy,
   cmpTypeDecreasedValue,
   cmpTypeDecreasedValueBy,
   cmpTypeChangedValue,
   cmpTypeUnchangedValue,
   cmpTypeUnknownInitialValue
} __attribute__((__packed__)) cmd_proc_scan_comparetype;

struct cmd_proc_scan_packet {
   uint32_t pid;
   uint8_t valueType;
   uint8_t compareType;
   uint32_t lenData;
} __attribute__((packed));
#define CMD_PROC_SCAN_PACKET_SIZE 10

struct cmd_proc_info_packet {
    uint32_t pid;
} __attribute__((packed));
struct cmd_proc_info_response {
    uint32_t pid;
    char name[40];
    char path[64];
    char titleid[16];
    char contentid[64];
} __attribute__((packed));
#define CMD_PROC_INFO_PACKET_SIZE 4
#define CMD_PROC_INFO_RESPONSE_SIZE 188

struct cmd_proc_alloc_packet {
    uint32_t pid;
    uint32_t length;
} __attribute__((packed));
struct cmd_proc_alloc_response {
    uint64_t address;
} __attribute__((packed));
#define CMD_PROC_ALLOC_PACKET_SIZE 8
#define CMD_PROC_ALLOC_RESPONSE_SIZE 8

struct cmd_proc_free_packet {
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_PROC_FREE_PACKET_SIZE 16

// debug
struct cmd_debug_attach_packet {
    uint32_t pid;
} __attribute__((packed));
#define CMD_DEBUG_ATTACH_PACKET_SIZE 4

struct cmd_debug_breakpt_packet {
    uint32_t index;
    uint32_t enabled;
    uint64_t address;
} __attribute__((packed));
#define CMD_DEBUG_BREAKPT_PACKET_SIZE 16

struct cmd_debug_watchpt_packet {
    uint32_t index;
    uint32_t enabled;
    uint32_t length;
    uint32_t breaktype;
    uint64_t address;
} __attribute__((packed));
#define CMD_DEBUG_WATCHPT_PACKET_SIZE 24

struct cmd_debug_stopthr_packet {
    uint32_t lwpid;
} __attribute__((packed));
#define CMD_DEBUG_STOPTHR_PACKET_SIZE 4

struct cmd_debug_resumethr_packet {
    uint32_t lwpid;
} __attribute__((packed));
#define CMD_DEBUG_RESUMETHR_PACKET_SIZE 4

struct cmd_debug_getregs_packet {
    uint32_t lwpid;
} __attribute__((packed));
#define CMD_DEBUG_GETREGS_PACKET_SIZE 4

struct cmd_debug_setregs_packet {
    uint32_t lwpid;
    uint32_t length;
} __attribute__((packed));
#define CMD_DEBUG_SETREGS_PACKET_SIZE 8

struct cmd_debug_stopgo_packet {
    uint32_t stop;
} __attribute__((packed));
#define CMD_DEBUG_STOPGO_PACKET_SIZE 4

struct cmd_debug_thrinfo_packet {
    uint32_t lwpid;
} __attribute__((packed));
struct cmd_debug_thrinfo_response {
    uint32_t lwpid;
    uint32_t priority;
    char name[32];
    // TODO: add more information
} __attribute__((packed));
#define CMD_DEBUG_THRINFO_PACKET_SIZE 4
#define CMD_DEBUG_THRINFO_RESPONSE_SIZE 40

// kern
struct cmd_kern_read_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_KERN_READ_PACKET_SIZE 12

struct cmd_kern_write_packet {
    uint64_t address;
    uint32_t length;
} __attribute__((packed));
#define CMD_KERN_WRITE_PACKET_SIZE 12

// console
struct cmd_console_print_packet {
    uint32_t length;
} __attribute__((packed));
#define CMD_CONSOLE_PRINT_PACKET_SIZE 4

struct cmd_console_notify_packet {
    uint32_t messageType;
    uint32_t length;
} __attribute__((packed));
#define CMD_CONSOLE_NOTIFY_PACKET_SIZE 8

struct cmd_console_info_response {
    // todo
} __attribute__((packed));
#define CMD_CONSOLE_INFO_RESPONSE_SIZE 8

#define MAX_BREAKPOINTS 30
#define MAX_WATCHPOINTS 4

struct debug_breakpoint {
    uint32_t enabled;
    uint64_t address;
    uint8_t original;
};

struct debug_watchpoint {
    uint32_t enabled;
    uint64_t address;
    uint8_t breaktype;
    uint8_t length;
};

struct debug_context {
    int pid;
    int dbgfd;
    struct debug_breakpoint breakpoints[MAX_BREAKPOINTS];
    // XXX: use actual __dbreg64 structure please
    struct {
        uint64_t dr[16];
    } watchdata;
};

struct server_client {
    int id;
    int fd;
    int debugging;
    struct sockaddr_in client;
    struct debug_context dbgctx;
};

#endif

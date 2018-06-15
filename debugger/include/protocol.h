// golden
// 6/12/2018
//

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <ps4.h>
#include "crc32.h"

#define PACKET_MAGIC    0xFFAABBCC

#define CMD_PROC_LIST	    	0xBDAA0001
#define CMD_PROC_READ	    	0xBDAA0002
#define CMD_PROC_WRITE	    	0xBDAA0003
#define RPC_PROC_INFO	    	0xBDAA0004
#define RPC_PROC_INTALL	    	0xBDAA0005
#define RPC_PROC_CALL	    	0xBDAA0006
#define CMD_PROC_PROTECT    	0xBDAA0007

#define CMD_DEBUG_ATTACH        0xBDBB0001
#define CMD_DEBUG_DETACH        0xBDBB0002
#define CMD_DEBUG_STOP          0xBDBB0003
#define CMD_DEBUG_RESUME        0xBDBB0004
#define CMD_DEBUG_BREAKPT       0xBDBB0005
#define CMD_DEBUG_WATCHPT       0xBDBB0006
#define CMD_DEBUG_THREADS       0xBDBB0007
#define CMD_DEBUG_STOPTHR       0xBDBB0008
#define CMD_DEBUG_RESUMETHR     0xBDBB0009
#define CMD_DEBUG_GETREGS       0xBDBB000A
#define CMD_DEBUG_SETREGS       0xBDBB000B
#define CMD_DEBUG_GETFREGS      0xBDBB000C
#define CMD_DEBUG_SETFREGS      0xBDBB000D
#define CMD_DEBUG_GETDBGREGS    0xBDBB000E
#define CMD_DEBUG_SETDBGREGS    0xBDBB000F

#define CMD_KERN_BASE	    	0xBDCC0001
#define CMD_KERN_READ           0xBDCC0002
#define CMD_KERN_WRITE	       	0xBDCC0003

#define CMD_CONSOLE_REBOOT      0xBDDD0001
#define CMD_CONSOLE_END         0xBDDD0002

#define VALID_CMD(cmd)          (((cmd & 0xFF000000) >> 24) == 0xBD)
#define VALID_PROC_CMD(cmd)     (((cmd & 0x00FF0000) >> 16) == 0xAA)
#define VALID_DEBUG_CMD(cmd)    (((cmd & 0x00FF0000) >> 16) == 0xBB)
#define VALID_KERN_CMD(cmd)     (((cmd & 0x00FF0000) >> 16) == 0xCC)
#define VALID_CONSOLE_CMD(cmd)	(((cmd & 0x00FF0000) >> 16) == 0xDD)

#define CMD_SUCCESS				0x80000000
#define CMD_ERROR	        	0xF0000001
#define CMD_TOO_MUCH_DATA		0xF0000002
#define CMD_DATA_NULL			0xF0000003

#define RPC_FATAL_STATUS(s) ((s >> 28) == 15)

struct cmd_packet {
	uint32_t magic;
    uint32_t cmd;
    uint32_t crc;
	uint32_t datalen;
	// (field not actually part of packet, comes after)
	uint8_t *data;
} __attribute__((packed));

#define CMD_PACKET_SIZE 16

#endif

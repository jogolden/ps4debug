// golden
// 6/12/2018
//

#include "net.h"

int net_send_data(int fd, void *data, int length) {
    uint32_t left = length;
	uint32_t offset = 0;
	uint32_t sent = 0;

	while (left > 0) {
		if (left > NET_MAX_LENGTH) {
			sent = sceNetSend(fd, data + offset, NET_MAX_LENGTH, 0);
		} else {
			sent = sceNetSend(fd, data + offset, left, 0);
		}

		if (!sent && !errno) {
			return 0;
		}

		offset += sent;
		left -= sent;
	}

	return offset;
}

int net_recv_data(int fd, void *data, int length, int force) {
	uint32_t left = length;
	uint32_t offset = 0;
	uint32_t recv = 0;

	while (left > 0) {
		if (left > NET_MAX_LENGTH) {
			recv = sceNetRecv(fd, data + offset, NET_MAX_LENGTH, 0);
		} else {
			recv = sceNetRecv(fd, data + offset, left, 0);
		}

		if (!recv) {
			if (!errno) {
				return 0;
			}

			if (!force) {
				return offset;
			}
		}

		offset += recv;
		left -= recv;
	}

	return offset;
}

int net_send_status(int fd, uint32_t status) {
	uint32_t d = status;
	if (net_send_data(fd, &d, sizeof(uint32_t)) == sizeof(uint32_t)) {
		return 0;
	} else {
		return 1;
	}
}

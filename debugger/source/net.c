// golden
// 6/12/2018
//

#include "net.h"

int net_send_data(int fd, void *data, int length) {
<<<<<<< HEAD
<<<<<<< HEAD
	int left = length;
	int offset = 0;
	int sent = 0;

	errno = NULL;

	while(left > 0) {
		if(left > NET_MAX_LENGTH) {
=======
=======
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
    int left = length;
	int offset = 0;
	int sent = 0;

	errno = NULL;

	while (left > 0) {
		if (left > NET_MAX_LENGTH) {
<<<<<<< HEAD
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
=======
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
			sent = write(fd, data + offset, NET_MAX_LENGTH);
		} else {
			sent = write(fd, data + offset, left);
		}

<<<<<<< HEAD
<<<<<<< HEAD
		if(sent <= 0 && errno && errno != EWOULDBLOCK) {
=======
		if (sent <= 0 && errno) {
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
=======
		if (sent <= 0 && errno) {
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
			return 0;
		} else {
			offset += sent;
			left -= sent;
		}
	}

	return offset;
}

#include "kdbg.h"

int net_recv_data(int fd, void *data, int length, int force) {
	int left = length;
	int offset = 0;
	int recv = 0;
<<<<<<< HEAD
=======

	errno = NULL;
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7

	errno = NULL;

<<<<<<< HEAD
	while(left > 0) {
		if(left > NET_MAX_LENGTH) {
=======
	while (left > 0) {
		if (left > NET_MAX_LENGTH) {
<<<<<<< HEAD
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
=======
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
			recv = read(fd, data + offset, NET_MAX_LENGTH);
		} else {
			recv = read(fd, data + offset, left);
		}

<<<<<<< HEAD
<<<<<<< HEAD
		if(recv <= 0) {
			if(force) {
=======
		if (recv <= 0) {
			if (force) {
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
=======
		if (recv <= 0) {
			if (force) {
>>>>>>> cbcc9ea97c51653385f543e30e1a30abbc253df7
				if(errno && errno != EWOULDBLOCK) {
					return 0;
				}
			} else {
				return offset;
			}
		} else {
			offset += recv;
			left -= recv;
		}
	}

	return offset;
}

int net_send_status(int fd, uint32_t status) {
	uint32_t d = status;

	return net_send_data(fd, &d, sizeof(uint32_t));
}

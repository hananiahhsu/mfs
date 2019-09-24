// Copyright 2019 MesaTEE Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include "multifs.h"
#include "common.h"
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>

#include <atomic>


static std::atomic_uint32_t sequece(0);

int _mfslibc_querysupport(const char* filename)
{
	if (filename == NULL) {
		return MFSSUP_TYPE_EINVAL;
	}

	mfssrv_command_query_in queryin = {};

	mfssrv_command_query_out queryout = {};
	queryout.type = MFSSUP_TYPE_EINVAL;

	size_t rtrecv = 0;

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_QUERY,
		&queryin, sizeof(queryin), &queryout, sizeof(queryout), &rtrecv);
	if (ret == -1 || rtrecv != sizeof(queryout)) {
		return -1;
	}

	return queryout.type;
}

int _mfslibc_ipccommand(uint32_t cmd, const void* sendbuf,
	size_t sendsize, void* recvbuf, size_t recvsize, size_t *recved)
{
	int ret = -1;
	int sock = -1;

	do 
	{
		sock = _mfslibc_connsrv();
		if (sock == -1) {
			break;
		}

		int rtsend = _mfslibc_sendmsg(sock, cmd, sendbuf, sendsize);
		if (rtsend != sendsize) {
			break;
		}

		int rtrecv = _mfslibc_recvmsg(sock, cmd, recvbuf, recvsize);
		if (rtrecv == -1) {
			break;
		}

		if (recved != NULL) {
			*recved = rtrecv;
		}

		ret = 0;
	} while (false);

	if (sock != -1)
	{
		_mfslibc_closeconn(sock);
	}
	
	return ret;
}

int _mfslibc_connsrv()
{
	int sockfd = socket(PF_UNIX, SOCK_STREAM, 0);

	sockaddr_un address = {};
 	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, MFSSRV_SOCK_NAME);

	int result = connect(sockfd, (sockaddr *)&address, sizeof(address));
	if (result == -1) {
		return -1;
	}

	return sockfd;
}

int _mfslibc_closeconn(int sockfd)
{
	if (sockfd == -1)	{
		errno = EINVAL;
		return -1;
	}

	int ret = close(sockfd);
	return ret;
}

size_t _mfslibc_sendmsg(int sockfd, uint32_t cmd, const void* buf, size_t size)
{
	if (sockfd == -1) {
		errno = EINVAL;
		return -1;
	}

	mfssrv_command_header hdr = {};
	hdr.magic = MFSSRV_HEADER_MAGIC;
	hdr.version = MFSSRV_PROTO_VERSION;
	hdr.mode = MFSSRV_OP_REQUEST;
	hdr.command = cmd;
	hdr.payload = size;
	hdr.error = 0;
	hdr.sequence = sequece++;
	hdr.reserved = 0;

	size_t send = _senddata_withslice(sockfd, &hdr, sizeof(hdr));
	if (send != sizeof(hdr)) {
		return -1;
	}

	send = 0;
	if (buf != NULL && size != 0) {
		send = _senddata_withslice(sockfd, buf, size);
		if (send != size) {
			return -1;
		}
	}

	return send;
}

size_t _mfslibc_recvmsg(int sockfd, uint32_t cmd, void* buf, size_t size)
{
	if (sockfd == -1) {
		errno = EINVAL;
		return -1;
	}

	mfssrv_command_header hdr = {};
	size_t recv = _recvdata_withslice(sockfd, &hdr, sizeof(hdr));
	if (recv != sizeof(hdr)) {
		errno = EREMOTEIO;
		return -1;
	}

	if (hdr.magic != MFSSRV_HEADER_MAGIC) {
		errno = EPROTO;
		return -1;
	}

	if (hdr.version != MFSSRV_PROTO_VERSION) {
		errno = EPROTONOSUPPORT;
		return -1;
	}

	if (hdr.mode != MFSSRV_OP_ANSWER) {
		errno = EPROTO;
		return -1;
	}

	if (hdr.command != cmd)	{
		errno = EPROTO;
		return -1;
	}

	// todo
	errno = hdr.error;
	if (hdr.error != 0) {
		return 0;
	}

	recv = 0;
	if (hdr.payload <= size
		&& buf != NULL
		&& size != 0) {
		recv = _recvdata_withslice(sockfd, buf, hdr.payload);
		if (recv != hdr.payload) {
			return -1;
		}
	}

	return recv;
}

int _mfslibc_getopmode(const char * mode)
{
	int omode = 0;
	int oflags = 0;

	switch (*mode)
	{
	case 'r':
		omode = O_RDONLY;
		break;
	case 'w':
		omode = O_WRONLY;
		oflags = O_CREAT | O_TRUNC;
		break;
	case 'a':
		omode = O_WRONLY;
		oflags = O_CREAT | O_APPEND;
		break;
	default:
		errno = EINVAL;
		return 0;
	}

	for (int i = 1; i < 7; ++i)	{
		switch (*++mode) {
		case '\0':
			break;
		case '+':
			omode = O_RDWR;
			continue;
		case 'x':
			oflags |= O_EXCL;
			continue;
		case 'b':
			continue;
		case 'm':
			continue;
		case 'c':
			continue;
		case 'e':
			oflags |= O_CLOEXEC;
			continue;
		default:
			/* Ignore.  */
			continue;
		}
		break;
	}

	return (omode | oflags);
}

void _mfslibc_seterrno(int err)
{
	errno = err;
}

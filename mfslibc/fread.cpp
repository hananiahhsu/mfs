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


#include <errno.h>
#include "multifs.h"
#include "common.h"


size_t MFSAPI mfs_fread(void* ptr, size_t size, size_t count, MFS_FILE* stream)
{
	CHECK_MFS_FILE(stream, 0);

	if (ptr == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (stream->_local == 1) {
		// for local mode
		size_t ret = fread(ptr, size, count, stream->_file);
		return ret;
	}

	size_t ret = 0;
	int sock = -1;

	do
	{
		if (size == 0 || count == 0) {
			break;
		}

		sock = _mfslibc_connsrv();
		if (sock == -1) {
			break;
		}

		const uint32_t cmd = MFSSRV_COMMAND_READ;

		mfssrv_command_read_in readin = {};
		readin.fd = stream->_fd;
		readin.size = size;
		readin.count = count;

		size_t rtsend = _mfslibc_sendmsg(sock, cmd, &readin, sizeof(readin));
		if (rtsend != sizeof(readin)) {
			break;
		}

		mfssrv_command_read_out readout = {};
		size_t rtrecv = _mfslibc_recvmsg(sock, cmd, &readout, sizeof(readout));
		if (rtrecv != sizeof(readout)) {
			break;
		}

		size_t totalsize = size * readout.count;
		rtrecv = _recvdata_withslice(sock, ptr, totalsize);
		if (rtrecv != totalsize) {
			break;
		}

		ret = readout.count;
	} while (false);

	if (sock != -1) {
		_mfslibc_closeconn(sock);
	}

	return ret;
}
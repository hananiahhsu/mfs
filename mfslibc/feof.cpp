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


int MFSAPI mfs_feof(MFS_FILE* stream)
{
	CHECK_MFS_FILE(stream, EOF);

	if (stream->_local == 1) {
		// for local mode
		size_t ret = feof(stream->_file);
		return ret;
	}

	off_t offset = mfs_ftello(stream);
	if (offset == -1) {
		return 0;
	}

	mfssrv_command_statfd_in statfdin = {};
	statfdin.fd = stream->_fd;

	mfssrv_command_stat_out statout = {};

	size_t rtrecv = 0;

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_STATFD,
		&statfdin, sizeof(statfdin), &statout, sizeof(statout), &rtrecv);
	if (rtrecv != sizeof(statout)) {
		return 0;
	}

	if (statout.stbuf.st_size == offset) {
		return offset;
	}

	return 0;
}
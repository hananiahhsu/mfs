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


int MFSAPI mfs_fseeko(MFS_FILE *stream, off_t offset, int whence)
{
	CHECK_MFS_FILE(stream, EOF);

	if (stream->_local == 1) {
		// for local mode
		size_t ret = fseeko(stream->_file, offset, whence);
		return ret;
	}

	mfssrv_command_seek_in seekin = {};
	seekin.fd = stream->_fd;
	seekin.off = offset;
	seekin.whence = whence;

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_SEEK,
		&seekin, sizeof(seekin), NULL, 0, NULL);
	if (ret == -1) {
		return -1;
	}

	return 0;
}

int MFSAPI mfs_fseek(MFS_FILE* stream, long int offset, int fromwhere)
{
	CHECK_MFS_FILE(stream, EOF);

	int ret = mfs_fseeko(stream, offset, fromwhere);
	return ret;
}
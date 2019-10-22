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


off_t MFSAPI mfs_ftello(MFS_FILE* stream)
{
	CHECK_MFS_FILE(stream, EOF);

	if (stream->_local == 1) {
		return ftello(stream->_file);
	}

	mfssrv_command_tell_in tellin = {};
	mfssrv_command_tell_out tellout = {};

	size_t rtrecv = 0;

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_TELL,
		&tellin, sizeof(tellin), &tellout, sizeof(tellout), &rtrecv);
	if (rtrecv != sizeof(tellout)) {
		return -1;
	}

	return tellout.offset;
}

long MFSAPI mfs_ftell(MFS_FILE* stream)
{
	CHECK_MFS_FILE(stream, EOF);

	return mfs_ftello(stream);
}
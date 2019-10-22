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
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>


int MFSAPI mfs_open(const char* filename, int flags)
{
	if (filename == NULL) {
		errno = EINVAL;
		return -1;
	}

	int len = strlen(filename);
	if (len >= PATH_MAX) {
		errno = EINVAL;
		return -1;
	}

	int sup = _mfslibc_querysupport(filename);
	if (sup == MFSSUP_TYPE_NOTMFSTYPE) {
		// for local mode
		int fd = open(filename, flags, 0777);
		return fd;
	}

	if (sup != MFSSUP_TYPE_SUPMFSTYPE) {
		errno = EOPNOTSUPP;
		return -1;
	}

	size_t rtrecv = 0;

	mfssrv_command_open_in openin = {};
	openin.mode = flags;
	strcpy(openin.filepath, filename);

	mfssrv_command_open_out openout = {};

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_OPEN,
		&openin, sizeof(openin), &openout, sizeof(openout), &rtrecv);
	if (rtrecv != sizeof(openout)) {
		return -1;
	}

	return openout.fd;
}

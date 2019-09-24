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
#include <errno.h>
#include <sys/file.h>


int MFSAPI mfs_flock(int fd, int operation)
{
	if (fd < 0) {
		errno = EINVAL;
		return -1;
	}

	if (!MFSSRV_REMOTEFD_CHECK(fd)) {
		// for local mode
		int ret = flock(fd, operation);
		return ret;
	}

	mfssrv_command_lock_in lockin = {};
	lockin.fd = fd;
	lockin.operation = operation;
	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_LOCK,
		&lockin, sizeof(lockin), NULL, 0, NULL);
	if (ret == -1) {
		return -1;
	}

	return 0;
}
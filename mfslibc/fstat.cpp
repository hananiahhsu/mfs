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


#include <string.h>
#include <errno.h>
#include "multifs.h"


int MFSAPI mfs_fstat(int fd, struct stat *stbuf)
{
	if (fd < 0) {
		errno = EINVAL;
		return -1;
	}

	if (!MFSSRV_REMOTEFD_CHECK(fd)) {
		// for local mode
		int ret = fstat(fd, stbuf);
		return ret;
	}

	mfssrv_command_statfd_in statfdin = {};
	statfdin.fd = fd;

	mfssrv_command_stat_out statout = {};

	size_t rtrecv = 0;

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_STAT,
		&statfdin, sizeof(statfdin), &statout, sizeof(statout), &rtrecv);
	if (rtrecv != sizeof(statout)) {
		return -1;
	}

	memcpy(stbuf, &statout.stbuf, sizeof(struct stat));

	return 0;
}

int MFSAPI mfs_stat(const char* filename, struct stat* stbuf)
{
	if (filename == NULL
		|| stbuf == NULL) {
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
		int ret = stat(filename, stbuf);
		return ret;
	}

	if (sup != MFSSUP_TYPE_SUPMFSTYPE) {
		errno = EOPNOTSUPP;
		return -1;
	}

	mfssrv_command_stat_in statin = {};
	strcpy(statin.filepath, filename);

	mfssrv_command_stat_out statout = {};

	size_t rtrecv = 0;

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_STAT,
		&statin, sizeof(statin), &statout, sizeof(statout), &rtrecv);
	if (rtrecv != sizeof(statout)) {
		return -1;
	}

	memcpy(stbuf, &statout.stbuf, sizeof(struct stat));

	return 0;
}
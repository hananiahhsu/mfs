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
#include <unistd.h>
#include <string.h>
#include <errno.h>


MFS_FILE* MFSAPI mfs_fdopen(int fd, const char* mode)
{
	if (fd < 0 || mode == NULL) {
		errno = EINVAL;
		return NULL;
	}

	MFS_FILE *result = (MFS_FILE *)malloc(sizeof(MFS_FILE));
	if (result == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	memset(result, 0, sizeof(MFS_FILE));
	result->_magic = MFS_IO_MAGIC;
	result->_file = NULL;
	result->_fd = fd;
	result->_local = 0;
	result->_errno = 0;
	result->_openmode = _mfslibc_getopmode(mode);

	if (!MFSSRV_REMOTEFD_CHECK(fd)) {
		// for local mode
		result->_local = 1;
		result->_file = fdopen(fd, mode);
		if (result->_file == NULL) {
			free(result);
			result = NULL;
		}
	}

	return result;
}
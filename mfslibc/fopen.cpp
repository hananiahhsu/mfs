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
#include <fcntl.h>
#include <string.h>


MFS_FILE* MFSAPI mfs_fopen(const char* filename, const char* mode)
{
	if (filename == NULL || mode == NULL) {
		errno = EINVAL;
		return NULL;
	}

	int len = strlen(filename);
	if (len >= PATH_MAX) {
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
	result->_fd = -1;
	result->_local = 0;
	result->_errno = 0;
	result->_openmode = _mfslibc_getopmode(mode);

	int sup = _mfslibc_querysupport(filename);
	if (sup != MFSSUP_TYPE_SMFS) {
		// for local mode
		result->_local = 1;
		result->_file = fopen(filename, mode);
		if (result->_file == NULL) {
			free(result);
			result = NULL;
		} else {
			result->_fd = fileno(result->_file);
		}
	} else {
		result->_fd = mfs_open(filename, result->_openmode);
		if (result->_fd == -1) {
			free(result);
			result = NULL;
		}
	}

	return result;
}
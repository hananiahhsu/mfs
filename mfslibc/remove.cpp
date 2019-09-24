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

int MFSAPI mfs_remove(const char* filename)
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
	if (sup != MFSSUP_TYPE_SMFS) {
		// for local mode
		int ret = remove(filename);
		return ret;
	}

	mfssrv_command_remove_in removein = {};
	strcpy(removein.filepath, filename);

	int ret = _mfslibc_ipccommand(MFSSRV_COMMAND_REMOVE,
		&removein, sizeof(removein), NULL, 0, NULL);
	if (ret == -1) {
		return -1;
	}

	return 0;
}

int MFSAPI mfs_removewitherase(const char* filename)
{
	MFS_FILE* file = mfs_fopen(filename, "r+");
	if (file == NULL) {
		return -1;
	}

	// todo

	mfs_fclose(file);
	mfs_remove(filename);

	return 0;
}
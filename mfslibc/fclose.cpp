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
#include <fcntl.h>


int MFSAPI mfs_fclose(MFS_FILE* stream)
{
	CHECK_MFS_FILE(stream, EOF);

	int ret = EOF;

	if (stream->_local == 1) {
		if (stream->_file != NULL) {
			ret = fclose(stream->_file);
		}
	} else {
		ret = mfs_close(stream->_fd);
	}

	free(stream);
	
	return ret;
}
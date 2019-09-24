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


/**
* File: multifs_interface.h
* Description:
*     Interface for file API
*/

#pragma once

#ifndef _MULTIFS_INTERFACE_H_
#define _MULTIFS_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define MFSAPI

#ifndef EOF
#define EOF        (-1)
#endif

#ifndef SEEK_SET
#define SEEK_SET    0
#endif

#ifndef SEEK_CUR
#define SEEK_CUR    1
#endif

#ifndef SEEK_END
#define SEEK_END    2
#endif


struct MFS_FILE;

#ifdef __cplusplus
extern "C" {
#endif

int MFSAPI mfs_open(const char* filename, int flags);
int MFSAPI mfs_remove(const char* filename);
int MFSAPI mfs_removewitherase(const char* filename);
int MFSAPI mfs_stat(const char* filename, struct stat *stbuf);

int MFSAPI mfs_fstat(int fd, struct stat* stbuf);
int MFSAPI mfs_close(int fd);
int MFSAPI mfs_flock(int fd, int operation);
MFS_FILE* MFSAPI mfs_fdopen(int fd, const char* mode);

int MFSAPI mfs_fseek(MFS_FILE* stream, long int offset, int whence);
int MFSAPI mfs_fseeko(MFS_FILE *stream, off_t offset, int whence);

int MFSAPI mfs_fileno(MFS_FILE *stream);

MFS_FILE* MFSAPI mfs_fopen(const char* filename, const char* mode);
size_t MFSAPI mfs_fwrite(const void* ptr, size_t size,
	size_t count, MFS_FILE* stream);

size_t MFSAPI mfs_fread(void* ptr, size_t size,
	size_t count, MFS_FILE* stream);

long MFSAPI mfs_ftell(MFS_FILE* stream);
off_t MFSAPI mfs_ftello(MFS_FILE* stream);

int MFSAPI mfs_fflush(MFS_FILE* stream);
int MFSAPI mfs_ferror(MFS_FILE* stream);
int MFSAPI mfs_feof(MFS_FILE* stream);
void MFSAPI mfs_clearerr(MFS_FILE* stream);
int MFSAPI mfs_fclose(MFS_FILE* stream);


#ifdef __cplusplus
}
#endif

#endif // _MULTIFS_INTERFACE_H_

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

#pragma once

#ifndef _MULITFS_H_
#define _MULITFS_H_


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mfslibc_interface.h"
#include "mfssrv_proto.h"



#define MFS_IO_MAGIC		0x012E4A04

typedef struct MFS_FILE {
	int _magic;		/* MFS_IO_MAGIC */
	int _openmode;	/* the file open mode flag */
	int _fd;		/* fd */
	int _local;		/* if local file, the value is 1 */
	int _errno;		/* the error number */
	FILE *_file;	/* if local mode, the value is fopen result */
	//char *filename;	/* */
} MFS_FILE;


#ifdef MFSIO_DEBUG
# define CHECK_MFS_FILE(FILE, RET) do {	\
    if ((FILE) == NULL					\
	|| ((FILE)->_magic != MFS_IO_MAGIC)	\
      {									\
	errno = EINVAL;						\
	return RET;							\
      }									\
  } while (0)
#else
# define CHECK_MFS_FILE(FILE, RET) do { } while (0)
#endif


int _mfslibc_querysupport(const char* filename);
int _mfslibc_ipccommand(uint32_t cmd, const void* sendbuf,
	size_t sendsize, void* recvbuf, size_t recvsize, size_t *recved);

int _mfslibc_connsrv();
int _mfslibc_closeconn(int sock);

size_t _mfslibc_sendmsg(int sock, uint32_t cmd,
	const void* buf, size_t size);
size_t _mfslibc_recvmsg(int sock, uint32_t cmd,
	void* buf, size_t size);

int _mfslibc_getopmode(const char* mode);

void _mfslibc_seterrno(int err);


#endif // _MULITFS_H_

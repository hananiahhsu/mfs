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
* File: mfssrv_proto.h
* Description:
*     communication protocol define between mfslibc and mfssrv
*/

#pragma once

#ifndef _MFSSRV_PROTO_H_
#define _MFSSRV_PROTO_H_

#include <stdint.h>
#include <limits.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	MFSSRV_COMMAND_QUERY = 0,	/* IN | OUT */
	MFSSRV_COMMAND_OPEN,		/* IN | OUT */
	MFSSRV_COMMAND_CLOSE,		/* IN */
	MFSSRV_COMMAND_REMOVE,		/* IN */
	MFSSRV_COMMAND_READ,		/* IN | OUT */
	MFSSRV_COMMAND_WRITE,		/* IN | OUT */
	MFSSRV_COMMAND_FLUSH,		/* IN */
	MFSSRV_COMMAND_TRUNCATE,	/* IN */
	MFSSRV_COMMAND_STAT,		/* IN | OUT */
	MFSSRV_COMMAND_STATFD,		/* IN | OUT */
	MFSSRV_COMMAND_LOCK,		/* IN */
	MFSSRV_COMMAND_SEEK,		/* IN */
	MFSSRV_COMMAND_TELL,		/* IN | OUT */
	MFSSRV_COMMAND_MAX,			/* */
} mfssrv_command_e;

typedef enum {
	MFSSRV_OP_REQUEST = 1,
	MFSSRV_OP_ANSWER,
} mfssrv_opmode_e;

typedef enum
{
	MFSSUP_TYPE_EINVAL = 0,			/* invalid argument */
	MFSSUP_TYPE_ESERVICE,			/* no mfs service or mfs error */
	MFSSUP_TYPE_NOTMFSTYPE,			/* not mfs type filepath */
	MFSSUP_TYPE_NOTSUPMFSTYPE,		/* mfs extend type, but not supported type */
	MFSSUP_TYPE_SUPMFSTYPE,			/* mfs extend type, and supported type*/
}mfssup_type_e;

/* the mask of extend support for fd value */
#define MFSSRV_REMOTEFD_FLAG			0x7F000000
#define MFSSRV_REMOTEFD_MASK			0xFF000000
#define MFSSRV_REMOTEFD_CHECK(fd)		(((fd) & MFSSRV_REMOTEFD_MASK) == MFSSRV_REMOTEFD_FLAG)

#define MFSSRV_REMOTEFD_MASK2			0x00FFFFFF
#define MFSSRV_REMOTEFD_GETVALUE(fd)	((fd) & MFSSRV_REMOTEFD_MASK2)
#define MFSSRV_REMOTEFD_MAKERFD(pid)	((pid) | MFSSRV_REMOTEFD_FLAG)

#define MFSSRV_HEADER_MAGIC				0x012E4AC4
#define MFSSRV_PROTO_VERSION			1

#define MFSSRV_SOCK_NAME				"/tmp/MFS{748C330F-9C0C-4F71-9353-42E4630866D0}"


#pragma pack(1)
typedef struct _mfssrv_command_header {
	uint32_t magic;			/* MFSSRV_HEADER_MAGIC */
	uint32_t version;
	uint32_t mode;
	uint32_t command;
	uint32_t payload;
	uint32_t error;
	uint32_t sequence;
	uint32_t reserved;
}mfssrv_command_header;

typedef struct _mfssrv_command_query_in {
	char filepath[PATH_MAX];
} mfssrv_command_query_in;

typedef struct _mfssrv_command_query_out {
	mfssup_type_e type;
}mfssrv_command_query_out;


typedef struct _mfssrv_command_open_in {
	mode_t mode;
	char filepath[PATH_MAX];
} mfssrv_command_open_in;

typedef struct _mfssrv_command_open_out {
	int fd;
} mfssrv_command_open_out;


typedef struct _mfssrv_command_close_in {
	int fd;
}mfssrv_command_close_in;


typedef struct _mfssrv_command_remove_in {
	char filepath[PATH_MAX];
} mfssrv_command_remove_in;


typedef struct _mfssrv_command_read_in {
	int fd;
	size_t size;
	size_t count;
} mfssrv_command_read_in;

typedef struct _mfssrv_command_read_out {
	size_t count;
	char buf[0];
} mfssrv_command_read_out;


typedef struct _mfssrv_command_write_in {
	int fd;
	size_t size;
	size_t count;
	char buf[0];
} mfssrv_command_write_in;

typedef struct _mfssrv_command_write_out {
	size_t count;
} mfssrv_command_write_out;


typedef struct _mfssrv_command_flush_in {
	int fd;
}mfssrv_command_flush_in;


typedef struct _mfssrv_command_truncate_in {
	int fd;
	size_t size;
} mfssrv_command_truncate_in;


typedef struct _mfssrv_command_stat_in {
	char filepath[PATH_MAX];
} mfssrv_command_stat_in;

typedef struct _mfssrv_command_statfd_in {
	int fd;
} mfssrv_command_statfd_in;

typedef struct _mfssrv_command_stat_out {
	struct stat stbuf;
} mfssrv_command_stat_out;


typedef struct _mfssrv_command_lock_in {
	int fd;
	int operation;
}mfssrv_command_lock_in;


typedef struct _mfssrv_command_seek_in {
	int fd;
	off_t off;
	int whence;
}mfssrv_command_seek_in;


typedef struct _mfssrv_command_tell_in {
	int fd;
}mfssrv_command_tell_in;

typedef struct _mfssrv_command_tell_out {
	off_t offset;
}mfssrv_command_tell_out;

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif // _MFSSRV_PROTO_H_

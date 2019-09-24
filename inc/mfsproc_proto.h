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
* File: mfsproc_proto.h
* Description:
*     protocol define between mfssrv and multifs
*/

#pragma once

#ifndef _MFSPROC_PROTO_H_
#define _MFSPROC_PROTO_H_

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	MFS_COMMAND_OPEN = 0,		/* IN */
	MFS_COMMAND_CLOSE,			/* IN */
	MFS_COMMAND_REMOVE,			/* IN */
	MFS_COMMAND_READ,			/* IN | OUT*/
	MFS_COMMAND_WRITE,			/* IN | OUT */
	MFS_COMMAND_FLUSH,			/* no payload */
	MFS_COMMAND_TRUNCATE,		/* IN */
	MFS_COMMAND_STAT,			/* IN | OUT*/
	MFS_COMMAND_CACHE,
	MFS_COMMAND_LOG,
} multifs_command_e;

typedef enum {
	OP_REQUEST = 1,
	OP_ANSWER,
} multifs_opmode_e;


#define MULTIFS_HEADER_MAGIC	0x0132DE42
#define MULTIFS_PROTO_VERSION	1

#pragma pack(1)
typedef struct _mfsproc_command_header {
	uint32_t magic;
	uint32_t version;
	uint32_t mode;
	uint32_t command;
	uint32_t payload;
	uint32_t error;
	uint32_t sequence;
	uint32_t reserved;
}mfsproc_command_header;

typedef struct _multifs_command_open_in {
	mode_t mode;
	char filepath[PATH_MAX];
} multifs_command_open_in;

typedef struct _multifs_command_open_out {
	size_t size;
} multifs_command_open_out;

typedef struct _multifs_command_remove_in {
	char filepath[PATH_MAX];
} multifs_command_remove_in;

typedef struct _multifs_command_read_in {
	off_t offset;
	size_t size;
} multifs_command_read_in;

typedef struct _multifs_command_read_out {
	size_t size;
	char buf[0];
} multifs_command_read_out;

typedef struct _multifs_command_write_in {
	off_t offset;
	size_t size;
	char buf[0];
} multifs_command_write_in;

typedef struct _multifs_command_write_out {
	size_t size;
} multifs_command_write_out;

typedef struct _multifs_command_truncate_in {
	size_t size;
} multifs_command_truncate_in;

typedef struct _multifs_command_stat_in {
	char filepath[PATH_MAX];
} multifs_command_stat_in;

typedef struct _multifs_command_stat_out {
	struct stat stbuf;
} multifs_command_stat_out;

typedef struct _multifs_command_cache_in {
	size_t free_disk_size_m;
	char cachepath[PATH_MAX];
} multifs_command_cache_in;

typedef struct _multifs_command_log_in {
	char debug_mark[PATH_MAX];
} multifs_command_log_in;

#pragma pack()

#ifdef __cplusplus
}
#endif

#endif // _MFSPROC_PROTO_H_

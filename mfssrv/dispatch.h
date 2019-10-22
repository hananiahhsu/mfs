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

#ifndef _DISPATCH_H_
#define _DISPATCH_H_

#include <stddef.h>
#include <stdint.h>
#include "mfssrv_proto.h"
#include "mfsproc_proto.h"

#define ERR_EXIT(m)		\
do {					\
	perror(m);			\
	exit(EXIT_FAILURE); \
} while (0);

extern bool exitproc;

int dispatch_command(int sockfd, const mfssrv_command_header* libcreqhdr);

int dispatch_command_query(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_open(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_close(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_remove(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_read(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_write(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_flush(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_truncate(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_stat(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_statfd(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_lock(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_seek(int sockfd, const mfssrv_command_header *reqhdr, int& error);
int dispatch_command_tell(int sockfd, const mfssrv_command_header *reqhdr, int& error);

int do_init();
void do_uninit();

bool check_validfd(int sock, const mfssrv_command_header* reqhdr, int fd);
mfssup_type_e gettype_bypath(const char* opfilepath);
char* get_supprocpath_byopfilepath(const char* opfilepath);

void signal_handler(int sig);

// return the payload size
size_t msganswer_to_mfslibc(int sockfd, const mfssrv_command_header* reqhdr,
	const void* payloadbuf, size_t payloadsize, int error);

// return the payload size
size_t msgsend_to_mfsproc(int sockfd, uint32_t command,
	const void* payloadbuf,	size_t payloadsize, int error);

// return the payload size
size_t msgrecv_from_mfsproc(int sockfd, mfsproc_command_header* anshdr,
	void* payloadbuf, size_t payloadsize, int &error);

#endif // _DISPATCH_H_

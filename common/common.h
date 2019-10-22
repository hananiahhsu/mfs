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
* File: multifs_proto.h
* Description:
*     protocol define between mfssrv and multifs
*/

#pragma once

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>


#define SLICE_SIZE	(16 * 1024)

// Minimum and maximum macros
#ifndef __max
#define __max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef __min
#define __min(a,b) (((a) < (b)) ? (a) : (b))
#endif

inline size_t _senddata_withslice(int socksend, const void* buf, size_t size)
{
	size_t total = 0;
	const char* sendbuf = (const char*)buf;

	while (total < size) {
		size_t slice = __min((size - total), SLICE_SIZE);
		ssize_t snd = send(socksend, sendbuf, slice, 0);
		if (snd == -1) {
			break;
		}

		if (snd == 0) {
			break;
		}

		total += snd;
		sendbuf += snd;
	}

	return total;
}

inline size_t _recvdata_withslice(int sockrecv, void* buf, size_t size)
{
	size_t total = 0;
	char* recvbuf = (char*)buf;

	while (total < size) {
		size_t slice = __min((size - total), SLICE_SIZE);
		ssize_t rev = recv(sockrecv, recvbuf, slice, 0);
		if (rev == -1) {
			break;
		}

		if (rev == 0) {
			break;
		}

		total += rev;
		recvbuf += rev;
	}

	return total;
}

#endif // _COMMON_H_

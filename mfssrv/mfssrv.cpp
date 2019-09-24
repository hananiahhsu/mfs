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


#include "mfssrv.h"
#include "dispatch.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <map>


#define ERR_EXIT(m)		\
do {					\
	perror(m);			\
	exit(EXIT_FAILURE); \
} while (0);



int main(int argc, char* argv[])
{
	int listenfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		ERR_EXIT("mfs socket error");
	}

	unlink(MFSSRV_SOCK_NAME);
	sockaddr_un servaddr = {};
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, MFSSRV_SOCK_NAME);

	int ret = bind(listenfd, (sockaddr*)& servaddr, sizeof(servaddr));
	if (ret < 0) {
		ERR_EXIT("mfs bind error");
	}

	ret = listen(listenfd, SOMAXCONN);
	if (ret < 0) {
		ERR_EXIT("listen error");
	}

	if (!do_init()) {
		ERR_EXIT("mfs init error");
	}

	chmod(MFSSRV_SOCK_NAME, 00777);
	signal(SIGTERM, &signal_handler);
	signal(SIGHUP, &signal_handler);
	signal(SIGCHLD, &signal_handler);

	do {
		int connfd = accept(listenfd, NULL, NULL);
		if (connfd < 0) {
			if (errno == EINTR) {
				continue;
			}

			ERR_EXIT("mfs accept error");
		}

		dispatch_command(connfd);
	} while (!exitproc);

	do_uninit();

	return 0;
}
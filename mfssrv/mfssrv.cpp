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
#include "common.h"
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



int main(int argc, char* argv[])
{
	int listenfd = do_init();
	if (listenfd < 0) {
		ERR_EXIT("mfs init error\n");
	}

	signal(SIGTERM, &signal_handler);
	signal(SIGHUP, &signal_handler);
	signal(SIGCHLD, &signal_handler);
	signal(SIGINT, &signal_handler);

	do {
		int sock = accept(listenfd, NULL, NULL);
		if (sock < 0) {
			if (errno == EINTR) {
				continue;
			}

			ERR_EXIT("mfssrv accept error\n");
		}

		mfssrv_command_header srvhdr = {};
		size_t rsize = _recvdata_withslice(sock, &srvhdr, sizeof(srvhdr));
		if (rsize != sizeof(srvhdr)) {
			close(sock);
			continue;
		}

		dispatch_command(sock, &srvhdr);
	} while (!exitproc);

	do_uninit();

	return 0;
}
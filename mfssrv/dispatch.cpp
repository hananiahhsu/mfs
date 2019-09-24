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


#include "dispatch.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <map>
#include <atomic>
#include <thread>


typedef struct _mfsio_info {
	pid_t pid;
	int sockfd;
	int openmode;
	int error;
	off_t offset;
	size_t size;
	char filepath[PATH_MAX];
}mfsio_info;
static std::map<int, mfsio_info*>* fdmap = NULL;

typedef struct _protocol_prefix {
	const char* prefix;
	const char* supportfile;
	bool support;
}protocol_prefix;
static protocol_prefix protogroup[] = {
	{"s3://", "mfsproc-s3", true},
	{"nfs://", NULL, false},
	{"ftp://", NULL, false},
	{"samba://", NULL, false},
	{"ssh://", NULL, false},
};

#define THREAD_MAX_COUNT	4
std::thread* threadgroup[THREAD_MAX_COUNT] = { NULL };

static std::atomic_uint32_t prosequece(0);
bool exitproc(false);

static void thread_task();



bool do_init()
{
	if (fdmap != NULL) {
		delete fdmap;
	}

	fdmap = new(std::nothrow) std::map<int, mfsio_info*>;
	if (fdmap == NULL) {
		return false;
	}

	for (int i = 0; i < THREAD_MAX_COUNT; i++) {
		threadgroup[i] = new(std::nothrow) std::thread(&thread_task);
		if (threadgroup[i] == NULL) {
			break;
		}
	}

	return true;
}

void do_uninit()
{
	if (fdmap != NULL) {
		delete fdmap;
		fdmap = NULL;
	}

	for (int i = 0; i < THREAD_MAX_COUNT; i++) {
		threadgroup[i]->join();
		delete threadgroup[i];
		threadgroup[i] = NULL;
	}
}

void signal_handler(int sig)
{
	if (sig == SIGCHLD) {
		do {
			int status = 0;
			pid_t pid = waitpid(-1, &status, WNOHANG);
			if (pid < 0) {
				break;
			}

			if (fdmap != NULL) {
				auto info = fdmap->find(pid);
				if (info != fdmap->end()) {
					close(info->second->sockfd);

					delete info->second;
					fdmap->erase(info);
				}
			}
		} while (true);
	} else if (sig == SIGTERM || sig == SIGHUP) {
		exitproc = true;
	}
}

bool check_validfd(int sock, const mfssrv_command_header* hdr, int fd)
{
	bool ret = false;

	if (!MFSSRV_REMOTEFD_CHECK(fd)) {
		ssize_t ssize = msgsend_to_mfslibc(sock, hdr, NULL, 0, EINVAL);
	} else {
		int index = MFSSRV_REMOTEFD_GETVALUE(fd);
		auto info = fdmap->find(index);
		if (info == fdmap->end()) {
			ssize_t ssize = msgsend_to_mfslibc(sock, hdr, NULL, 0, EINVAL);
		} else {
			ret = true;
		}
	}

	return ret;
}

mfssup_type_e gettype_bypath(const char* filepath)
{
	mfssup_type_e type = MFSSUP_TYPE_SNOTSUP;
	for (int i = 0; i < sizeof(protogroup) / sizeof(protogroup[0]); i++) {
		int preflen = strlen(protogroup[i].prefix);
		int cmp = strncmp(protogroup[i].prefix, filepath, preflen);
		if (cmp == 0) {
			if (protogroup[i].support) {
				type = MFSSUP_TYPE_SMFS;
			}

			break;
		}
	}

	return type;
}

const char* getsupproc_bypath(const char* filepath)
{
	const char *filename = NULL;
	for (int i = 0; i < sizeof(protogroup) / sizeof(protogroup[0]); i++) {
		int preflen = strlen(protogroup[i].prefix);
		int cmp = strncmp(protogroup[i].prefix, filepath, preflen);
		if (cmp == 0) {
			if (protogroup[i].support) {
				filename = protogroup[i].supportfile;
			}

			break;
		}
	}

	return filename;
}

size_t msgsend_to_mfslibc(int sockfd, const mfssrv_command_header* reqhdr,
	const void* payloadbuf, size_t paloadsize, int error)
{
	mfssrv_command_header anshdr = *reqhdr;
	anshdr.mode = MFSSRV_OP_ANSWER;
	anshdr.payload = paloadsize;
	anshdr.error = error;
	anshdr.reserved = 0;

	ssize_t ssize = _senddata_withslice(sockfd, &anshdr, sizeof(anshdr));
	if (ssize != sizeof(anshdr)) {
		return -1;
	}

	ssize = 0;
	if (payloadbuf != NULL && paloadsize != 0) {
		ssize = _senddata_withslice(sockfd, payloadbuf, paloadsize);
	}
	
	return ssize;
}

int dispatch_command(int sockfd)
{
	mfssrv_command_header srvhdr = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvhdr, sizeof(srvhdr));
	if (rsize != sizeof(srvhdr)) {
		return -1;
	}

	int result = -1;

	do 
	{
		if (srvhdr.magic != MFSSRV_HEADER_MAGIC) {
			errno = EPROTO;
			break;
		}

		if (srvhdr.version != MFSSRV_PROTO_VERSION) {
			errno = EPROTONOSUPPORT;
			break;
		}

		if (srvhdr.mode != MFSSRV_OP_REQUEST) {
			errno = EPROTO;
			break;
		}

		if (srvhdr.command >= MFSSRV_COMMAND_MAX) {
			errno = EPROTO;
			break;
		}

		if (srvhdr.error != 0)	{
			errno = EPROTO;
			break;
		}

		typedef int (*dispatch_routine)(int sockfd, const mfssrv_command_header * srvhdr);
		typedef struct _dispatch_table {
			int command;
			dispatch_routine routine;
			size_t min_payload;
		}dispatch_table;
		static dispatch_table disptbl[] = {
			{MFSSRV_COMMAND_QUERY, &dispatch_command_query, sizeof(mfssrv_command_query_in)},
			{MFSSRV_COMMAND_LOCK, &dispatch_command_lock, sizeof(mfssrv_command_lock_in)},
			{MFSSRV_COMMAND_SEEK, &dispatch_command_seek, sizeof(mfssrv_command_seek_in)},
			{MFSSRV_COMMAND_TELL, &dispatch_command_tell, sizeof(mfssrv_command_tell_in)},
			{MFSSRV_COMMAND_CLOSE, &dispatch_command_close, sizeof(mfssrv_command_close_in)},

			{MFSSRV_COMMAND_OPEN, &dispatch_command_open, sizeof(mfssrv_command_open_in)},
			{MFSSRV_COMMAND_REMOVE, &dispatch_command_remove, sizeof(mfssrv_command_remove_in)},
			{MFSSRV_COMMAND_READ, &dispatch_command_read, sizeof(mfssrv_command_read_in)},
			{MFSSRV_COMMAND_WRITE, &dispatch_command_write, sizeof(mfssrv_command_write_in)},
			{MFSSRV_COMMAND_FLUSH, &dispatch_command_flush, sizeof(mfssrv_command_flush_in)},
			{MFSSRV_COMMAND_TRUNCATE, &dispatch_command_truncate, sizeof(mfssrv_command_truncate_in)},
			{MFSSRV_COMMAND_STAT, &dispatch_command_stat, sizeof(mfssrv_command_stat_in)},
			{MFSSRV_COMMAND_STATFD, &dispatch_command_statfd, sizeof(mfssrv_command_statfd_in)},
		};

		for (int i=0; i<sizeof(disptbl)/sizeof(disptbl[0]); i++) {
			if (srvhdr.command == disptbl[i].command) {
				if (srvhdr.payload < disptbl[i].min_payload) {
					errno = EPROTO;
					break;
				}

				result = disptbl[i].routine(sockfd, &srvhdr);
				break;
			}
		}
	} while (false);

	if (result == -1) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, &srvhdr, NULL, 0, errno);
	}

	close(sockfd);
	
	return result;
}

int dispatch_command_query(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_query_in queryin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &queryin, sizeof(queryin));
	if (rsize != sizeof(queryin)) {
		errno = EPROTO;
		return -1;
	}

	mfssrv_command_query_out queryout = {};
	queryout.type = gettype_bypath(queryin.filepath);

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, &queryout, sizeof(queryout), 0);
	if (ssize != sizeof(queryout)) {
		return -1;
	}

	return 0;
}

int dispatch_command_open(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_open_in srvopenin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvopenin, sizeof(srvopenin));
	if (rsize != sizeof(srvopenin)) {
		errno = EPROTO;
		return -1;
	}

	int result = -1;
	int error = 0;

	mfssrv_command_open_out srvopenout = {};

	do 
	{
		char* curdir = get_current_dir_name();
		if (curdir == NULL) {
			error = errno;
			break;
		}

		int len = strlen(srvopenin.filepath);
		if (len >= PATH_MAX) {
			error = EINVAL;
			break;
		}

		const char* name = getsupproc_bypath(srvopenin.filepath);
		if (name == NULL) {
			error = ENOTSUP;
			break;
		}

		int fd[2] = {};
		int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
		if (ret < 0) {
			error = errno;
			break;
		}

		mfsio_info* info = new(std::nothrow)mfsio_info;
		if (info == NULL) {
			close(fd[0]);
			close(fd[1]);

			error = ENOMEM;
			break;
		}

		info->size = 0;
		info->error = 0;
		info->offset = 0;
		info->openmode = srvopenin.mode;
		info->sockfd = fd[0];
		strcpy(info->filepath, srvopenin.filepath);
		info->pid = fork();
		if (info->pid < 0) {
			close(fd[0]);
			close(fd[1]);
			delete info;

			error = errno;
			break;
		}
		else if (info->pid == 0) {
			close(fd[0]);
			prctl(PR_SET_PDEATHSIG, SIGKILL);

			char fullpath_subproc[PATH_MAX] = { 0 };
			strcpy(fullpath_subproc, curdir);
			strcat(fullpath_subproc, name);

			char paras[16] = {};
			sprintf(paras, "%d", fd[1]);

			int ret = execl(fullpath_subproc, fullpath_subproc, paras, NULL);
			printf("sub process execl failure, err = %d\n", errno);
			close(fd[1]);
			_exit(-1);
		}
		else {
			close(fd[1]);
			srvopenout.fd = -1;

			do 
			{
				mfsproc_command_header req_prochdr = {};
				req_prochdr.magic = MULTIFS_HEADER_MAGIC;
				req_prochdr.version = MULTIFS_PROTO_VERSION;
				req_prochdr.mode = OP_REQUEST;
				req_prochdr.command = MFS_COMMAND_OPEN;
				req_prochdr.error = 0;
				req_prochdr.sequence = prosequece++;
				req_prochdr.payload = sizeof(multifs_command_open_in);
				ssize_t ssize = _senddata_withslice(info->sockfd, &req_prochdr, sizeof(req_prochdr));
				if (ssize != sizeof(req_prochdr)) {
					error = errno;
					break;
				}

				multifs_command_open_in procopenin = {};
				procopenin.mode = srvopenin.mode;
				strcpy(procopenin.filepath, srvopenin.filepath);
				ssize = _senddata_withslice(info->sockfd, &procopenin, sizeof(procopenin));
				if (ssize != sizeof(procopenin)) {
					error = errno;
					break;
				}

				mfsproc_command_header ans_prochdr = {};
				rsize = _recvdata_withslice(info->sockfd, &ans_prochdr, sizeof(ans_prochdr));
				if (rsize != sizeof(ans_prochdr)) {
					error = errno;
					break;
				}

				error = ans_prochdr.error;
				if (ans_prochdr.error != 0) {
					break;
				}

				multifs_command_open_out procopenout = {};
				rsize = _recvdata_withslice(info->sockfd, &procopenout, sizeof(procopenout));
				if (rsize != sizeof(procopenout)) {
					error = errno;
					break;
				}

				info->size = procopenout.size;
				srvopenout.fd = MFSSRV_REMOTEFD_MAKERFD(info->pid);
				fdmap->insert(std::make_pair(info->pid, info));

				result = 0;
			} while (false);
		}
	} while (false);

	if (result == -1) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, error);
	} else {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, &srvopenout, sizeof(srvopenout), 0);
	}
	
	return result;
}

int dispatch_command_close(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_close_in srvclosein = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvclosein, sizeof(srvclosein));
	if (rsize != sizeof(srvclosein)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, srvclosein.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvclosein.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	close(it->second->sockfd);
	kill(it->first, SIGKILL);

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, 0);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_remove(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_remove_in srvremovein = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvremovein, sizeof(srvremovein));
	if (rsize != sizeof(srvremovein)) {
		errno = EPROTO;
		return -1;
	}

	int result = -1;
	int err = 0;

	do 
	{
		int len = strlen(srvremovein.filepath);
		if (len >= PATH_MAX) {
			ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
			break;
		}

		//========= todo =========
		int sockrecv = -1;
		int socksend = -1;

		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_REMOVE;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = sizeof(multifs_command_remove_in);
		ssize_t ssize = _senddata_withslice(socksend, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		multifs_command_remove_in procremovein = {};
		strcpy(procremovein.filepath, srvremovein.filepath);
		ssize = _senddata_withslice(socksend, &procremovein, sizeof(procremovein));
		if (ssize != sizeof(procremovein)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(sockrecv, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}

		err = ans_prochdr.error;
		if (ans_prochdr.error != 0) {
			break;
		}

		result = 0;
	} while (false);

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_read(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_read_in srvreadin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvreadin, sizeof(srvreadin));
	if (rsize != sizeof(srvreadin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, srvreadin.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvreadin.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	//========= todo =========
	int err = 0;

	do
	{
		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_READ;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = sizeof(multifs_command_read_in);
		ssize_t ssize = _senddata_withslice(it->second->sockfd, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		multifs_command_read_in procreadin = {};
		procreadin.offset = it->second->offset;
		procreadin.size = srvreadin.count * srvreadin.size;
		ssize = _senddata_withslice(it->second->sockfd, &procreadin, sizeof(procreadin));
		if (ssize != sizeof(procreadin)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(it->second->sockfd, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}

		multifs_command_read_out proreadout = {};
		rsize = _recvdata_withslice(it->second->sockfd, &proreadout, sizeof(proreadout));
		if (rsize != sizeof(proreadout)) {
			err = errno;
			break;
		}

		//read and send
		err = 0;
	} while (false);

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_write(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_write_in srvwritein = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvwritein, sizeof(srvwritein));
	if (rsize != sizeof(srvwritein)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, srvwritein.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvwritein.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	//========= todo =========
	int err = 0;

	do
	{
		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_WRITE;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = 0;
		ssize_t ssize = _senddata_withslice(it->second->sockfd, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(it->second->sockfd, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}

		err = 0;
	} while (false);

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_flush(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_flush_in flushin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &flushin, sizeof(flushin));
	if (rsize != sizeof(flushin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, flushin.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(flushin.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	int err = 0;

	do 
	{
		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_FLUSH;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = 0;
		ssize_t ssize = _senddata_withslice(it->second->sockfd, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(it->second->sockfd, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}

		err = 0;
	} while (false);
	
	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_truncate(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_truncate_in truncatein = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &truncatein, sizeof(truncatein));
	if (rsize != sizeof(truncatein)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, truncatein.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(truncatein.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	int err = 0;

	do
	{
		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_TRUNCATE;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = 0;
		ssize_t ssize = _senddata_withslice(it->second->sockfd, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(it->second->sockfd, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}

		err = 0;
	} while (false);

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_stat(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_stat_in srvstatin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvstatin, sizeof(srvstatin));
	if (rsize != sizeof(srvstatin)) {
		errno = EPROTO;
		return -1;
	}

	int len = strlen(srvstatin.filepath);
	if (len >= PATH_MAX) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	int err = 0;
	multifs_command_stat_out procstatout = {};

	do
	{
		//========= todo =========
		int sockrecv = -1;
		int socksend = -1;

		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_STAT;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = sizeof(multifs_command_stat_in);
		ssize_t ssize = _senddata_withslice(socksend, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		multifs_command_stat_in procstatin = {};
		strcpy(procstatin.filepath, srvstatin.filepath);
		ssize = _senddata_withslice(socksend, &procstatin, sizeof(procstatin));
		if (ssize != sizeof(procstatin)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(sockrecv, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}

		rsize = _recvdata_withslice(sockrecv, &procstatout, sizeof(procstatout));
		if (rsize != sizeof(procstatout)) {
			err = errno;
			break;
		}

		err = 0;
	} while (false);

	ssize_t ssize = 0;
	if (err == 0)
	{
		ssize = msgsend_to_mfslibc(sockfd, hdr, &procstatout, sizeof(procstatout), 0);
	}
	else {
		ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	}
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_statfd(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_statfd_in statin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &statin, sizeof(statin));
	if (rsize != sizeof(statin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, statin.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(statin.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	int err = 0;
	multifs_command_stat_out procstatout = {};

	do
	{
		mfsproc_command_header req_prochdr = {};
		req_prochdr.magic = MULTIFS_HEADER_MAGIC;
		req_prochdr.version = MULTIFS_PROTO_VERSION;
		req_prochdr.mode = OP_REQUEST;
		req_prochdr.command = MFS_COMMAND_STAT;
		req_prochdr.error = 0;
		req_prochdr.sequence = prosequece++;
		req_prochdr.payload = sizeof(multifs_command_stat_in);
		ssize_t ssize = _senddata_withslice(it->second->sockfd, &req_prochdr, sizeof(req_prochdr));
		if (ssize != sizeof(req_prochdr)) {
			err = errno;
			break;
		}

		multifs_command_stat_in procstatin = {};
		strcpy(procstatin.filepath, it->second->filepath);
		ssize = _senddata_withslice(it->second->sockfd, &procstatin, sizeof(procstatin));
		if (ssize != sizeof(procstatin)) {
			err = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = _recvdata_withslice(it->second->sockfd, &ans_prochdr, sizeof(ans_prochdr));
		if (rsize != sizeof(ans_prochdr)) {
			err = errno;
			break;
		}
		
		rsize = _recvdata_withslice(it->second->sockfd, &procstatout, sizeof(procstatout));
		if (rsize != sizeof(procstatout)) {
			err = errno;
			break;
		}

		err = 0;
	} while (false);

	ssize_t ssize = 0;
	if (err == 0)
	{
		ssize = msgsend_to_mfslibc(sockfd, hdr, &procstatout, sizeof(procstatout), 0);
	} else {
		ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, err);
	}
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_lock(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_lock_in srvlockin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvlockin, sizeof(srvlockin));
	if (rsize != sizeof(srvlockin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, srvlockin.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvlockin.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	//========= todo =========
	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, 0);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_seek(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_seek_in srvseekin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvseekin, sizeof(srvseekin));
	if (rsize != sizeof(srvseekin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, srvseekin.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvseekin.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	off_t newoff = it->second->offset;
	if (srvseekin.whence == SEEK_SET) {
		newoff = srvseekin.off;
	} else if (srvseekin.whence == SEEK_CUR){
		newoff += srvseekin.off;
	} else if (srvseekin.whence == SEEK_END) {
		newoff = it->second->size + srvseekin.off;
	}
	if (newoff > it->second->size) {
		newoff = it->second->size;
	}
	if (newoff < 0) {
		newoff = 0;
	}
	it->second->offset = newoff;
	
	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, 0);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

int dispatch_command_tell(int sockfd, const mfssrv_command_header* hdr)
{
	mfssrv_command_tell_in srvtellin = {};
	ssize_t rsize = _recvdata_withslice(sockfd, &srvtellin, sizeof(srvtellin));
	if (rsize != sizeof(srvtellin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, hdr, srvtellin.fd);
	if (!validfd) {
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvtellin.fd));
	if (it == fdmap->end()) {
		ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, NULL, 0, EINVAL);
		return -1;
	}

	mfssrv_command_tell_out srvtellout = {};
	srvtellout.offset = it->second->offset;

	ssize_t ssize = msgsend_to_mfslibc(sockfd, hdr, &srvtellout, sizeof(srvtellout), 0);
	if (ssize == -1) {
		return -1;
	}

	return 0;
}

void thread_task()
{

}
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
#include <fcntl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/file.h>
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
	int lockstat;
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
bool exitproc = false;
int listenfd = -1;
int lockfile = -1;

static void thread_task();


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
	} else if (sig == SIGTERM
		|| sig == SIGINT) {
		exitproc = true;
		close(listenfd);
		listenfd = -1;
	}
}

int do_init()
{
	lockfile = open("/tmp/mfssrv_singleproc.lock", O_CREAT | O_RDWR, 00666);
	if (lockfile == -1) {
		ERR_EXIT("the mfssrv lock file open failure!\n");
	}
	
	int ret = flock(lockfile, LOCK_EX | LOCK_NB);
	if (ret == -1) {
		if (EWOULDBLOCK == errno) {
			ERR_EXIT("the mfssrv already running!\n");
		}
	}

	listenfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		ERR_EXIT("mfs listen socket create error\n");
	}

	unlink(MFSSRV_SOCK_NAME);
	sockaddr_un servaddr = {};
	servaddr.sun_family = AF_UNIX;
	strcpy(servaddr.sun_path, MFSSRV_SOCK_NAME);

	ret = bind(listenfd, (sockaddr*)&servaddr, sizeof(servaddr));
	if (ret < 0) {
		ERR_EXIT("mfssrv bind error\n");
	}

	ret = listen(listenfd, SOMAXCONN);
	if (ret < 0) {
		close(listenfd);
		listenfd = -1;

		ERR_EXIT("mfssrv listen error\n");
	}

	chmod(MFSSRV_SOCK_NAME, 00666);

	if (fdmap != NULL) {
		delete fdmap;
		fdmap = NULL;
	}

	fdmap = new(std::nothrow) std::map<int, mfsio_info*>;
	if (fdmap == NULL) {
		close(listenfd);
		listenfd = -1;

		return listenfd;
	}

	for (int i = 0; i < THREAD_MAX_COUNT; i++) {
		threadgroup[i] = new(std::nothrow) std::thread(&thread_task);
		if (threadgroup[i] == NULL) {
			break;
		}
	}

	return listenfd;
}

void do_uninit()
{
	unlink(MFSSRV_SOCK_NAME);

	if (fdmap != NULL) {
		delete fdmap;
		fdmap = NULL;
	}

	for (int i = 0; i < THREAD_MAX_COUNT; i++) {
		threadgroup[i]->join();
		delete threadgroup[i];
		threadgroup[i] = NULL;
	}

	if (lockfile != -1) {
		flock(lockfile, LOCK_UN);
		close(lockfile);
		lockfile = -1;
	}
}

bool check_validfd(int sock, const mfssrv_command_header* reqhdr, int fd)
{
	bool ret = false;

	do {
		if (!MFSSRV_REMOTEFD_CHECK(fd)) {
			break;
		}
		
		int index = MFSSRV_REMOTEFD_GETVALUE(fd);
		auto info = fdmap->find(index);
		if (info == fdmap->end()) {
			break;
		}
		
		ret = true;
	} while (false);
	
	return ret;
}

mfssup_type_e gettype_bypath(const char* opfilepath)
{
	mfssup_type_e type = MFSSUP_TYPE_NOTSUPMFSTYPE;
	for (size_t i = 0; i < sizeof(protogroup) / sizeof(protogroup[0]); i++) {
		size_t preflen = strlen(protogroup[i].prefix);
		int cmp = strncmp(protogroup[i].prefix, opfilepath, preflen);
		if (cmp != 0) {
			continue;
		}

		if (!protogroup[i].support) {
			break;
		}

		char fullpath_subproc[PATH_MAX] = {};
		int cnt = readlink("/proc/self/exe", fullpath_subproc, PATH_MAX);
		if (cnt < 0 || cnt >= PATH_MAX) {
			printf("get self directory failure, err = %d\n", errno);
			break;
		}

		for (int i = cnt; i >= 0; i--) {
			if (fullpath_subproc[i] == '/') {
				fullpath_subproc[i + 1] = '\0';
				break;
			}
		}

		strcat(fullpath_subproc, protogroup[i].supportfile);
		int ret = access(fullpath_subproc, X_OK);
		if (ret != -1) {
			type = MFSSUP_TYPE_SUPMFSTYPE;
		}

		break;
	}

	return type;
}

char* get_supprocpath_byopfilepath(const char* opfilepath)
{
	char* supproc = NULL;

	for (size_t i = 0; i < sizeof(protogroup) / sizeof(protogroup[0]); i++) {
		size_t preflen = strlen(protogroup[i].prefix);
		int cmp = strncmp(protogroup[i].prefix, opfilepath, preflen);
		if (cmp != 0) {
			continue;
		}

		if (!protogroup[i].support) {
			break;
		}

		char fullpath_subproc[PATH_MAX] = {};
		int cnt = readlink("/proc/self/exe", fullpath_subproc, PATH_MAX);
		if (cnt < 0 || cnt >= PATH_MAX) {
			printf("get self directory failure, err = %d\n", errno);
			break;
		}

		for (int i = cnt; i >= 0; i--) {
			if (fullpath_subproc[i] == '/') {
				fullpath_subproc[i + 1] = '\0';
				break;
			}
		}

		strcat(fullpath_subproc, protogroup[i].supportfile);
		int ret = access(fullpath_subproc, X_OK);
		if (ret != -1) {
			supproc = new(std::nothrow) char[PATH_MAX];
			strcpy(supproc, fullpath_subproc);
		}

		break;
	}

	return supproc;
}

size_t msganswer_to_mfslibc(int sockfd, const mfssrv_command_header* reqhdr,
	const void* payloadbuf, size_t payloadsize, int error)
{
	mfssrv_command_header anshdr = *reqhdr;
	anshdr.mode = MFSSRV_OP_ANSWER;
	anshdr.payload = (uint32_t)payloadsize;
	anshdr.error = error;
	anshdr.reserved = 0;

	size_t ssize = _senddata_withslice(sockfd, &anshdr, sizeof(anshdr));
	if (ssize != sizeof(anshdr)) {
		return -1;
	}

	ssize = 0;
	if (payloadbuf != NULL && payloadsize != 0) {
		ssize = _senddata_withslice(sockfd, payloadbuf, payloadsize);
	}
	
	return ssize;
}

size_t msgsend_to_mfsproc(int sockfd, uint32_t command,
	const void* payloadbuf,	size_t payloadsize, int error)
{
	mfsproc_command_header req_prochdr = {};
	req_prochdr.magic = MULTIFS_HEADER_MAGIC;
	req_prochdr.version = MULTIFS_PROTO_VERSION;
	req_prochdr.mode = OP_REQUEST;
	req_prochdr.command = command;
	req_prochdr.error = error;
	req_prochdr.sequence = prosequece++;
	req_prochdr.payload = (uint32_t)payloadsize;
	req_prochdr.reserved = 0;

	size_t ssize = _senddata_withslice(sockfd, &req_prochdr, sizeof(req_prochdr));
	if (ssize != sizeof(req_prochdr)) {
		return -1;
	}

	ssize = 0;
	if (payloadbuf != NULL && payloadsize != 0) {
		ssize = _senddata_withslice(sockfd, payloadbuf, payloadsize);
	}

	return ssize;
}

size_t msgrecv_from_mfsproc(int sockfd, mfsproc_command_header* anshdr,
	void* payloadbuf, size_t payloadsize, int& error)
{
	size_t rsize = _recvdata_withslice(sockfd, anshdr, sizeof(mfsproc_command_header));
	if (rsize != sizeof(mfsproc_command_header)) {
		error = EPROTO;
		return -1;
	}

	if (anshdr->magic != MULTIFS_HEADER_MAGIC) {
		error = EPROTO;
		return -1;
	}

	if (anshdr->version != MULTIFS_PROTO_VERSION) {
		error = EPROTONOSUPPORT;
		return -1;
	}

	if (anshdr->mode != OP_ANSWER) {
		error = EPROTO;
		return -1;
	}

	if (anshdr->command >= MFS_COMMAND_MAX) {
		error = EPROTO;
		return -1;
	}

	if (anshdr->error != 0) {
		error = anshdr->error;
	}

	rsize = 0;
	size_t sizeread = __min(anshdr->payload, payloadsize);
	if (payloadbuf != NULL && payloadsize != 0) {
		rsize = _recvdata_withslice(sockfd, payloadbuf, sizeread);
		if (rsize != sizeread) {
			error = ENETUNREACH;
			return -1;
		}
	}

	// discard the redundant data
	size_t surplus = (anshdr->payload > payloadsize) ? (anshdr->payload - payloadsize) : 0;
	while (surplus > 0) {
		char buff[1024];
		size_t slice = __max(surplus, sizeof(buff));
		size_t datasize = _recvdata_withslice(sockfd, buff, slice);
		if (datasize != -1) {
			surplus -= datasize;
		}
	}
	
	return rsize;
}

int dispatch_command(int sockfd, const mfssrv_command_header* libcreqhdr)
{
	int result = -1;
	int err = 0;

	do 
	{
		if (libcreqhdr->magic != MFSSRV_HEADER_MAGIC) {
			err = EPROTO;
			break;
		}

		if (libcreqhdr->version > MFSSRV_PROTO_VERSION) {
			err = EPROTONOSUPPORT;
			break;
		}

		if (libcreqhdr->mode != MFSSRV_OP_REQUEST) {
			err = EPROTO;
			break;
		}

		if (libcreqhdr->command >= MFSSRV_COMMAND_MAX) {
			err = EPROTO;
			break;
		}

		if (libcreqhdr->error != 0)	{
			err = EPROTO;
			break;
		}

		typedef int (*dispatch_routine)(int sockfd, const mfssrv_command_header *libcreqhdr, int &error);
		typedef struct _dispatch_table {
			uint32_t command;
			dispatch_routine routine;
			size_t minpayload;
			bool asyncmode;
		}dispatch_table;
		static dispatch_table disptbl[] = {
			{MFSSRV_COMMAND_QUERY, &dispatch_command_query, sizeof(mfssrv_command_query_in), false},
			{MFSSRV_COMMAND_LOCK, &dispatch_command_lock, sizeof(mfssrv_command_lock_in), false},
			{MFSSRV_COMMAND_SEEK, &dispatch_command_seek, sizeof(mfssrv_command_seek_in), false},
			{MFSSRV_COMMAND_TELL, &dispatch_command_tell, sizeof(mfssrv_command_tell_in), false},
			{MFSSRV_COMMAND_CLOSE, &dispatch_command_close, sizeof(mfssrv_command_close_in), false},

			{MFSSRV_COMMAND_OPEN, &dispatch_command_open, sizeof(mfssrv_command_open_in), true},
			{MFSSRV_COMMAND_REMOVE, &dispatch_command_remove, sizeof(mfssrv_command_remove_in), true},
			{MFSSRV_COMMAND_READ, &dispatch_command_read, sizeof(mfssrv_command_read_in), true},
			{MFSSRV_COMMAND_WRITE, &dispatch_command_write, sizeof(mfssrv_command_write_in), true},
			{MFSSRV_COMMAND_FLUSH, &dispatch_command_flush, sizeof(mfssrv_command_flush_in), true},
			{MFSSRV_COMMAND_TRUNCATE, &dispatch_command_truncate, sizeof(mfssrv_command_truncate_in), true},
			{MFSSRV_COMMAND_STAT, &dispatch_command_stat, sizeof(mfssrv_command_stat_in), true},
			{MFSSRV_COMMAND_STATFD, &dispatch_command_statfd, sizeof(mfssrv_command_statfd_in), true},
		};

		for (size_t i = 0; i < sizeof(disptbl) / sizeof(disptbl[0]); i++) {
			if (libcreqhdr->command == disptbl[i].command) {
				if (libcreqhdr->payload < disptbl[i].minpayload) {
					err = EPROTO;
					break;
				}

				result = disptbl[i].routine(sockfd, libcreqhdr, err);
				break;
			}
		}
	} while (false);

	if (result == -1) {
		size_t ssize = msganswer_to_mfslibc(sockfd, libcreqhdr, NULL, 0, err);
	}

	close(sockfd);
	
	return result;
}

int dispatch_command_query(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_query_in srvqueryin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvqueryin, sizeof(srvqueryin));
	if (rsize != sizeof(srvqueryin)) {
		error = EPROTO;
		return -1;
	}

	mfssrv_command_query_out srvqueryout = {};
	srvqueryout.type = gettype_bypath(srvqueryin.filepath);

	size_t ssize = msganswer_to_mfslibc(sockfd, reqhdr, &srvqueryout, sizeof(srvqueryout), 0);
	return 0;
}

int dispatch_command_open(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;
	int result = -1;
	char* subproc = NULL;

	do 
	{
		mfssrv_command_open_in srvopenin = {};
		size_t rsize = _recvdata_withslice(sockfd, &srvopenin, sizeof(srvopenin));
		if (rsize != sizeof(srvopenin)) {
			error = EPROTO;
			break;
		}

		size_t len = strlen(srvopenin.filepath);
		if (len >= PATH_MAX) {
			error = EINVAL;
			break;
		}

		subproc = get_supprocpath_byopfilepath(srvopenin.filepath);
		if (subproc == NULL) {
			error = ENOTSUP;
			break;
		}

		int fd[2] = {};
		int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
		if (ret < 0) {
			error = errno;
			break;
		}

		pid_t pid = fork();
		if (pid < 0) {
			close(fd[0]);
			close(fd[1]);

			error = errno;
			break;
		} else if (pid == 0) {
			close(fd[0]);

			prctl(PR_SET_PDEATHSIG, SIGKILL);

			char paras[16] = {};
			sprintf(paras, "%d", fd[1]);

			int ret = execl(subproc, subproc, paras);
			if (ret == -1) {
				printf("sub process execl failure, err = %d\n", errno);
				_exit(-1);
			}
		} else {
			close(fd[1]);

			mfsproc_command_open_in procopenin = {};
			procopenin.mode = srvopenin.mode;
			strcpy(procopenin.filepath, srvopenin.filepath);

			size_t ssize = msgsend_to_mfsproc(fd[0], MFS_COMMAND_OPEN,
				&procopenin, sizeof(procopenin), 0);
			if (ssize != sizeof(procopenin)) {
				kill(pid, SIGKILL);
				close(fd[0]);
				error = errno;

				break;
			}

			mfsproc_command_header ans_prochdr = {};
			mfsproc_command_open_out procopenout = {};
			rsize = msgrecv_from_mfsproc(fd[0], &ans_prochdr
				, &procopenout, sizeof(procopenout), error);
			if (rsize != sizeof(procopenout)) {
				kill(pid, SIGKILL);
				close(fd[0]);

				break;
			}

			error = ans_prochdr.error;
			if (ans_prochdr.error != 0) {
				kill(pid, SIGKILL);
				close(fd[0]);
				break;
			}

			mfsio_info* info = new(std::nothrow)mfsio_info;
			if (info == NULL) {
				kill(pid, SIGKILL);
				close(fd[0]);
				error = ENOMEM;
				break;
			}

			info->pid = pid;
			info->size = 0;
			info->error = 0;
			info->offset = 0;
			info->lockstat = 0;
			info->openmode = srvopenin.mode;
			info->size = procopenout.size;
			info->sockfd = fd[0];
			strcpy(info->filepath, srvopenin.filepath);

			mfssrv_command_open_out srvopenout = {};
			srvopenout.fd = MFSSRV_REMOTEFD_MAKERFD(info->pid);
			fdmap->insert(std::make_pair(info->pid, info));

			ssize = msganswer_to_mfslibc(sockfd, reqhdr, &srvopenout, sizeof(srvopenout), 0);
			result = 0;
		}
	} while (false);

	if (subproc != NULL) {
		delete[] subproc;
	}

	return result;
}

int dispatch_command_close(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_close_in srvclosein = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvclosein, sizeof(srvclosein));
	if (rsize != sizeof(srvclosein)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvclosein.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvclosein.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	close(it->second->sockfd);
	kill(it->first, SIGKILL);

	size_t ssize = msganswer_to_mfslibc(sockfd, reqhdr, NULL, 0, 0);
	return 0;
}

int dispatch_command_remove(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;
	int result = -1;
	char* subproc = NULL;

	do {
		mfssrv_command_remove_in srvremovein = {};
		size_t rsize = _recvdata_withslice(sockfd, &srvremovein, sizeof(srvremovein));
		if (rsize != sizeof(srvremovein)) {
			error = EPROTO;
			break;
		}

		size_t len = strlen(srvremovein.filepath);
		if (len >= PATH_MAX) {
			error = EINVAL;
			break;
		}

		subproc = get_supprocpath_byopfilepath(srvremovein.filepath);
		if (subproc == NULL) {
			error = ENOTSUP;
			break;
		}

		int fd[2] = {};
		int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
		if (ret < 0) {
			error = errno;
			break;
		}

		pid_t pid = fork();
		if (pid < 0) {
			close(fd[0]);
			close(fd[1]);

			error = errno;
			break;
		} else if (pid == 0) {
			close(fd[0]);
			prctl(PR_SET_PDEATHSIG, SIGKILL);

			char paras[16] = {};
			sprintf(paras, "%d", fd[1]);

			int ret = execl(subproc, subproc, paras);
			if (ret == -1) {
				printf("sub process execl failure, err = %d\n", errno);
				_exit(-1);
			}
		} else {
			close(fd[1]);

			mfsproc_command_remove_in procremovein = {};
			strcpy(procremovein.filepath, srvremovein.filepath);

			size_t ssize = msgsend_to_mfsproc(fd[0], MFS_COMMAND_REMOVE,
				&procremovein, sizeof(procremovein), 0);
			if (ssize != sizeof(procremovein)) {
				error = errno;
				kill(pid, SIGKILL);
				close(fd[0]);
				break;
			}

			mfsproc_command_header ans_prochdr = {};
			rsize = msgrecv_from_mfsproc(fd[0], &ans_prochdr, NULL, 0, error);
			kill(pid, SIGKILL);
			close(fd[0]);
			if (rsize == -1) {
				break;
			}

			error = ans_prochdr.error;
			ssize = msganswer_to_mfslibc(sockfd, reqhdr, NULL, 0, error);

			result = 0;
		}
	} while (false);

	if (subproc != NULL) {
		delete[] subproc;
	}

	return result;
}

int dispatch_command_read(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_read_in srvreadin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvreadin, sizeof(srvreadin));
	if (rsize != sizeof(srvreadin)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvreadin.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvreadin.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	int ret = -1;

	do {
		mfsproc_command_read_out procreadout = {};

		mfssrv_command_read_out srvreadout = {};
		mfssrv_command_header anshdr = *reqhdr;

		if (srvreadin.count == 0 || srvreadin.size == 0) {
			srvreadout.count = 0;
			anshdr.payload = (uint32_t)sizeof(srvreadout);
		} else {
			mfsproc_command_read_in procreadin = {};
			procreadin.offset = it->second->offset;
			procreadin.size = srvreadin.count * srvreadin.size;

			size_t ssize = msgsend_to_mfsproc(it->second->sockfd, MFS_COMMAND_READ,
				&procreadin, sizeof(procreadin), 0);
			if (ssize != sizeof(procreadin)) {
				error = errno;
				break;
			}

			mfsproc_command_header ans_prochdr = {};
			
			rsize = msgrecv_from_mfsproc(it->second->sockfd, &ans_prochdr,
				&procreadout, sizeof(procreadout), error);
			if (rsize != sizeof(procreadout)) {
				break;
			}

			srvreadout.count = procreadout.size / srvreadin.size;
			size_t retsize = srvreadout.count * srvreadin.size;

			anshdr.payload = (uint32_t)sizeof(srvreadout) + (uint32_t)retsize;
		}
		
		anshdr.mode = MFSSRV_OP_ANSWER;
		anshdr.error = error;
		anshdr.reserved = 0;
		size_t ssize = _senddata_withslice(sockfd, &anshdr, sizeof(anshdr));
		if (ssize != sizeof(anshdr)) {
			error = errno;
			break;
		}

		ssize = _senddata_withslice(sockfd, &srvreadout, sizeof(srvreadout));
		if (ssize != sizeof(srvreadout)) {
			error = errno;
			break;
		}

		// read from mfsproc and write to mfslibc
		if (srvreadin.count != 0 && srvreadin.size != 0) {
			size_t toread = procreadout.size;
			size_t tosend = (procreadout.size / srvreadin.size) * srvreadin.size;
			
			while (toread > 0) {
				char tmpbuf[4096];
				size_t slice = __min(sizeof(tmpbuf), toread);
				rsize = _recvdata_withslice(it->second->sockfd, tmpbuf, slice);
				if (rsize == -1) {
					error = EPROTO;
					break;
				}

				toread -= rsize;

				if (tosend > 0)	{
					slice = __min(sizeof(rsize), tosend);
					ssize = _senddata_withslice(sockfd, tmpbuf, slice);
					if (ssize == -1) {
						error = EPROTO;
						break;
					}

					tosend -= ssize;
				}
			}
		}

		ret = 0;
	} while (false);

	return ret;
}

int dispatch_command_write(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_write_in srvwritein = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvwritein, sizeof(srvwritein));
	if (rsize != sizeof(srvwritein)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvwritein.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvwritein.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	int result = -1;

	do {
		mfssrv_command_write_out srvwriteout = {};
		if (srvwritein.count == 0 || srvwritein.size == 0) {
			srvwriteout.count = 0;
		} else {
			mfsproc_command_write_in procwritein = {};
			procwritein.offset = it->second->offset;
			procwritein.size = srvwritein.count * srvwritein.size;

			mfsproc_command_header req_prochdr = {};
			req_prochdr.magic = MULTIFS_HEADER_MAGIC;
			req_prochdr.version = MULTIFS_PROTO_VERSION;
			req_prochdr.mode = OP_REQUEST;
			req_prochdr.command = MFS_COMMAND_WRITE;
			req_prochdr.error = error;
			req_prochdr.sequence = prosequece++;
			req_prochdr.payload = (uint32_t)sizeof(mfsproc_command_write_in) + (uint32_t)(procwritein.size);
			req_prochdr.reserved = 0;
			size_t ssize = _senddata_withslice(it->second->sockfd, &req_prochdr, sizeof(req_prochdr));
			if (ssize != sizeof(req_prochdr)) {
				break;
			}

			ssize = _senddata_withslice(it->second->sockfd, &procwritein, sizeof(procwritein));
			if (ssize != sizeof(procwritein)) {
				break;
			}

			size_t torecv = procwritein.size;
			while (torecv > 0) {
				char tmpbuf[4096];
				size_t slice = __min(sizeof(tmpbuf), torecv);
				rsize = _recvdata_withslice(sockfd, tmpbuf, slice);
				if (rsize != slice) {
					error = EPROTO;
					break;
				}

				torecv -= rsize;
				ssize = _senddata_withslice(it->second->sockfd, tmpbuf, rsize);
				if (ssize != rsize) {
					break;
				}
			}

			mfsproc_command_write_out procwriteout = {};
			rsize = _recvdata_withslice(it->second->sockfd, &procwriteout, sizeof(procwriteout));
			if (rsize != sizeof(procwriteout)) {
				error = EPROTO;
				break;
			}

			srvwriteout.count = procwriteout.size / srvwritein.size;
		}

		size_t ssize = msganswer_to_mfslibc(sockfd, reqhdr,
			&srvwriteout, sizeof(srvwriteout), 0);

		result = 0;
	} while (false);

	return result;
}

int dispatch_command_flush(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_flush_in srvflushin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvflushin, sizeof(srvflushin));
	if (rsize != sizeof(srvflushin)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvflushin.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvflushin.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	int result = -1;

	do {
		size_t ssize = msgsend_to_mfsproc(it->second->sockfd, MFS_COMMAND_FLUSH,
			NULL, 0, 0);
		if (ssize == -1) {
			error = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = msgrecv_from_mfsproc(it->second->sockfd, &ans_prochdr,
			NULL, 0, error);
		if (rsize == -1) {
			break;
		}

		error = ans_prochdr.error;
		if (ans_prochdr.error != 0) {
			break;
		}

		ssize = msganswer_to_mfslibc(sockfd, reqhdr,
			NULL, 0, 0);

		result = 0;
	} while (false);

	return result;
}

int dispatch_command_truncate(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_truncate_in srvtruncatein = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvtruncatein, sizeof(srvtruncatein));
	if (rsize != sizeof(srvtruncatein)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvtruncatein.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvtruncatein.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	int result = -1;

	do {
		mfsproc_command_truncate_in procstruncatein = {};
		procstruncatein.size = srvtruncatein.size;
		size_t ssize = msgsend_to_mfsproc(it->second->sockfd, MFS_COMMAND_TRUNCATE,
			&procstruncatein, sizeof(procstruncatein), 0);
		if (ssize != sizeof(procstruncatein)) {
			error = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		rsize = msgrecv_from_mfsproc(it->second->sockfd, &ans_prochdr,
			NULL, 0, error);
		if (rsize == -1) {
			break;
		}

		error = ans_prochdr.error;
		if (ans_prochdr.error != 0) {
			break;
		}

		ssize = msganswer_to_mfslibc(sockfd, reqhdr,
			NULL, 0, 0);

		result = 0;
	} while (false);

	return result;
}

int dispatch_command_stat(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;
	int result = -1;
	char* subproc = NULL;

	do {
		mfssrv_command_stat_in srvstatin = {};
		size_t rsize = _recvdata_withslice(sockfd, &srvstatin, sizeof(srvstatin));
		if (rsize != sizeof(srvstatin)) {
			error = EPROTO;
			return -1;
		}

		size_t len = strlen(srvstatin.filepath);
		if (len >= PATH_MAX) {
			error = EINVAL;
			return -1;
		}

		subproc = get_supprocpath_byopfilepath(srvstatin.filepath);
		if (subproc == NULL) {
			error = ENOTSUP;
			break;
		}

		int fd[2] = {};
		int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
		if (ret < 0) {
			error = errno;
			break;
		}

		pid_t pid = fork();
		if (pid < 0) {
			close(fd[0]);
			close(fd[1]);

			error = errno;
			break;
		} else if (pid == 0) {
			close(fd[0]);
			prctl(PR_SET_PDEATHSIG, SIGKILL);

			char paras[16] = {};
			sprintf(paras, "%d", fd[1]);

			ret = execl(subproc, subproc, paras);
			if (ret == -1) {
				printf("sub process execl failure, err = %d\n", errno);
				_exit(-1);
			}
		} else {
			close(fd[1]);

			mfsproc_command_stat_in procstatin = {};
			strcpy(procstatin.filepath, srvstatin.filepath);

			size_t ssize = msgsend_to_mfsproc(fd[0], MFS_COMMAND_STAT,
				&procstatin, sizeof(procstatin), 0);
			if (ssize != sizeof(procstatin)) {
				error = errno;
				kill(pid, SIGKILL);
				close(fd[0]);
				break;
			}

			mfsproc_command_header ans_prochdr = {};
			mfsproc_command_stat_out procstatout = {};
			rsize = msgrecv_from_mfsproc(fd[0], &ans_prochdr,
				&procstatout, sizeof(procstatout), error);
			kill(pid, SIGKILL);
			close(fd[0]);
			if (rsize != sizeof(procstatout)) {
				break;
			}

			error = ans_prochdr.error;

			mfssrv_command_stat_out srvstatout = {};
			memcpy(&srvstatout.stbuf, &procstatout.stbuf, sizeof(struct stat));
			ssize = msganswer_to_mfslibc(sockfd, reqhdr,
				&srvstatout, sizeof(srvstatout), 0);

			result = 0;
		}
	} while (false);

	if (subproc != NULL) {
		delete[] subproc;
	}

	return result;
}

int dispatch_command_statfd(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_statfd_in srvstatin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvstatin, sizeof(srvstatin));
	if (rsize != sizeof(srvstatin)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvstatin.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvstatin.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	int result = -1;

	do {
		mfsproc_command_stat_in procstatin = {};
		strcpy(procstatin.filepath, it->second->filepath);
		size_t ssize = msgsend_to_mfsproc(it->second->sockfd, MFS_COMMAND_STAT,
			&procstatin, sizeof(procstatin), 0);
		if (ssize != sizeof(procstatin)) {
			error = errno;
			break;
		}

		mfsproc_command_header ans_prochdr = {};
		mfsproc_command_stat_out procstatout = {};
		rsize = msgrecv_from_mfsproc(it->second->sockfd, &ans_prochdr,
			&procstatout, sizeof(procstatout), error);
		if (rsize != sizeof(procstatout)) {
			break;
		}

		error = ans_prochdr.error;
		if (ans_prochdr.error != 0) {
			break;
		}

		mfssrv_command_stat_out srvstatout = {};
		memcpy(&srvstatout.stbuf, &procstatout.stbuf, sizeof(struct stat));
		ssize = msganswer_to_mfslibc(sockfd, reqhdr,
			&srvstatout, sizeof(srvstatout), 0);

		result = 0;
	} while (false);

	return result;
}

int dispatch_command_lock(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_lock_in srvlockin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvlockin, sizeof(srvlockin));
	if (rsize != sizeof(srvlockin)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvlockin.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvlockin.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	// now, not support this operation, need add support later
	size_t ssize = msganswer_to_mfslibc(sockfd, reqhdr, NULL, 0, 0);

	return 0;
}

int dispatch_command_seek(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_seek_in srvseekin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvseekin, sizeof(srvseekin));
	if (rsize != sizeof(srvseekin)) {
		errno = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvseekin.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvseekin.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
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
	if (newoff < 0) {
		error = EINVAL;
		return -1;
	}

	it->second->offset = newoff;
	size_t ssize = msganswer_to_mfslibc(sockfd, reqhdr, NULL, 0, 0);

	return 0;
}

int dispatch_command_tell(int sockfd, const mfssrv_command_header* reqhdr, int& error)
{
	error = 0;

	mfssrv_command_tell_in srvtellin = {};
	size_t rsize = _recvdata_withslice(sockfd, &srvtellin, sizeof(srvtellin));
	if (rsize != sizeof(srvtellin)) {
		error = EPROTO;
		return -1;
	}

	bool validfd = check_validfd(sockfd, reqhdr, srvtellin.fd);
	if (!validfd) {
		error = EINVAL;
		return -1;
	}

	auto it = fdmap->find(MFSSRV_REMOTEFD_GETVALUE(srvtellin.fd));
	if (it == fdmap->end()) {
		error = EINVAL;
		return -1;
	}

	mfssrv_command_tell_out srvtellout = {};
	srvtellout.offset = it->second->offset;
	size_t ssize = msganswer_to_mfslibc(sockfd, reqhdr, &srvtellout, sizeof(srvtellout), 0);

	return 0;
}

void thread_task()
{

}
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include "mfslibc_interface.h"
#include "mfssrv_proto.h"


int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("parameter errror!\n"
			"%s filepath\n", argv[1]);

		return -1;
	}
	printf("======================================================\n");

	MFS_FILE* file = NULL;

	const char* testfile = argv[1];
	size_t totalsize = 0;

	do {
		int fd = mfs_open(testfile, O_RDWR | O_CREAT);
		if (fd == -1) {
			printf("mfs_open failure, error=%d\n", errno);
			return -1;
		}
		printf("mfs_open fd=%d\n", fd);

		file = mfs_fdopen(fd, "rw+");
		if (file == NULL) {
			printf("mfs_fdopen failure, error=%d\n", errno);
			mfs_close(fd);
			return -1;
		}
		printf("MFS_FILE* =%p\n", file);

		char buf1[789] = {};
		memset(buf1, 0x11, sizeof(buf1));
		size_t size = mfs_fwrite(buf1, 1, sizeof(buf1), file);
		if (size == -1) {
			printf("mfs_fwrite failure, error=%d\n", errno);
			break;
		}
		totalsize += size;

		int ret = mfs_fflush(file);
		if (ret == -1) {
			printf("mfs_fflush failure, error=%d\n", errno);
			break;
		}

		char buf2[4096] = {};
		memset(buf2, 0xFF, sizeof(buf2));
		for (int i = 0; i < 5; i++) {
			size = mfs_fwrite(buf2, 1, sizeof(buf2), file);
			if (size == -1) {
				break;
			}

			totalsize += size;
		}

		char buf3[3326] = {};
		memset(buf3, 0xCC, sizeof(buf3));
		size = mfs_fwrite(buf3, 1, sizeof(buf3), file);
		if (size == -1) {
			printf("mfs_fwrite failure, error=%d\n", errno);
			break;
		}
		totalsize += size;
		mfs_fflush(file);
	} while (false);

	if (file != NULL) {
		mfs_fclose(file);
		file = NULL;

		struct stat st = {};
		int ret = mfs_stat(testfile, &st);
		if (ret == -1) {
			printf("mfs_stat failure, error=%d\n", errno);
		}

		printf("writed size = %ld\nfile size = %ld\n",
			st.st_size, totalsize);
	}

	printf("demo exit.\n");
	printf("======================================================\n");

    return 0;
}

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
* File: multifs_interface.h
* Description:
*     Interface for file API
*/

#pragma once

#ifndef _MULTIFS_INTERFACE_H_
#define _MULTIFS_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define MFSAPI

#ifndef EOF
#define EOF        (-1)
#endif

#ifndef SEEK_SET
#define SEEK_SET    0
#endif

#ifndef SEEK_CUR
#define SEEK_CUR    1
#endif

#ifndef SEEK_END
#define SEEK_END    2
#endif


struct MFS_FILE;

#ifdef __cplusplus
extern "C" {
#endif


/* mfs_open
 *  Purpose: open existing file or create a new one (see c++ open documentation for more details).
 *
 *  Parameters:
 *      filename - [IN] the name of the file to open/create. the format like following format:
 *         [for local file] /tmp/tmpfile                
 *         [for Amazon S3 protocol] s3://yourak:yoursk@xxxx.com/path1/name1	
 *         [for NFS protocol] nfs://user:pass@xxxx.com/path2/name2 
 *      flags - [IN] open flag. the meaning of these flags is exactly as specified in open().
 * 
 *  Note - now, support s3 format and local format
 * 
 *  Return value:
 *     int  -  a file descriptor, nonnegative integer that is used in subsequent calls (mfs_fstat, mfs_close, mfs_fdopen etc.),
 *             or -1 if an error occurred (in which case, errno is set appropriately)
*/
int MFSAPI mfs_open(const char* filename, int flags);

/* mfs_remove
 *  Purpose: delete a file from the file system (see c++ remove documentation for more details).
 *
 *  Parameters:
 *      filename - [IN] the name of the file to remvoe. the format like following format:
 *         [for local file] /tmp/tmpfile                
 *         [for Amazon S3 protocol] s3://yourak:yoursk@xxxx.com/path1/name1	
 *         [for NFS protocol] nfs://user:pass@xxxx.com/path2/name2 
 * 
 *  Return value:
 *     int  - result, 0 - success, -1 - there was an error, check errno for the error code
*/
int MFSAPI mfs_remove(const char* filename);

/* mfs_removewitherase
 *  Purpose: erase and delete a file from the file system.
 *
 *  Parameters:
 *      filename - [IN] the name of the file to erase and remove. the format like following format:
 *         [for local file] /tmp/tmpfile                
 *         [for Amazon S3 protocol] s3://yourak:yoursk@xxxx.com/path1/name1	
 *         [for NFS protocol] nfs://user:pass@xxxx.com/path2/name2 
 *
 *  Return value:
 *     int  - result, 0 - success, -1 - there was an error, check errno for the error code
*/
//int MFSAPI mfs_removewitherase(const char* filename);

/* mfs_stat
 *  Purpose: get a stat information (see c++ stat documentation for more details).
 *
 *  Parameters:
 *      filename - [IN] the name of the file to get stat information. the format like following format:
 *         [for local file] /tmp/tmpfile                
 *         [for Amazon S3 protocol] s3://yourak:yoursk@xxxx.com/path1/name1	
 *         [for NFS protocol] nfs://user:pass@xxxx.com/path2/name2 
 *
 *  Return value:
 *     int  - result, 0 - success, -1 - there was an error, check errno for the error code
*/
int MFSAPI mfs_stat(const char* filename, struct stat *stbuf);

/* mfs_fstat
 *  Purpose: get a stat information (see c++ fstat documentation for more details).
 *
 *  Parameters:
 *      fd - [IN] the file descriptor by mfs_open return.
 *      stbuf- [OUT] pointer to the struct stat
 *
 *  Return value:
 *     int  - result, 0 - success, -1 - there was an error, check errno for the error code
*/
int MFSAPI mfs_fstat(int fd, struct stat* stbuf);

/* mfs_close
 *  Purpose: close an file descriptor (see c++ close documentation for more details).
 *           after a call to this function, the handle is invalid even if an error is returned
 *
 *  Parameters:
 *      fd - [IN] the file descriptor by mfs_open return.
 *
 *  Return value:
 *     int  - result, 0 - file was closed successfully, -1 - there were errors during the operation
*/
int MFSAPI mfs_close(int fd);

/* mfs_flock
 *  Purpose: apply or remove an advisory lock on an open file (see c++ flock documentation for more details).
 *
 *  Parameters:
 *      fd - [IN] the file descriptor by mfs_open return.
 *      operation - [IN] one of the following: LOCK_SH, LOCK_EX, LOCK_UN
 *  NOTE - this interface only support local file. otherwise, it return success but not do any operat.
 *
 *  Return value:
 *     int  - result, 0 - file was closed successfully, -1 - there were errors during the operation
*/
int MFSAPI mfs_flock(int fd, int operation);

/* mfs_fdopen
 *  Purpose: associate a stream with a file descriptor (see c++ fdopen documentation for more details).
 *
 *  Parameters:
 *      fd - [IN] the file descriptor by mfs_open return.
 *      mode - [IN] open mode. the meaning of these flags is exactly as specified in fopen()
 *
 *  Return value:
 *     int  - result, 0 - success, -1 - there was an error, check errno for the error code
*/
MFS_FILE* MFSAPI mfs_fdopen(int fd, const char* mode);

/* mfs_fseek
 *  Purpose: set the current value of the position indicator of the file (see c++ fseek documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *      offset - [IN] the new required value, relative to the whence parameter
 *      whence - [IN] the origin from which to calculate the offset (SEEK_SET, SEEK_CUR or SEEK_END)
 *
 *  Return value:
 *     int  - result, 0 on success, -1 in case of an error - check mfs_ferror for error code
*/
int MFSAPI mfs_fseek(MFS_FILE* stream, long int offset, int whence);

/* mfs_fseeko
 *  Purpose: set the current value of the position indicator of the file (see c++ fseek documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *      offset - [IN] the new required value, relative to the whence parameter
 *      whence - [IN] the origin from which to calculate the offset (SEEK_SET, SEEK_CUR or SEEK_END)
 *
 *  Return value:
 *     int  - result, 0 on success, -1 in case of an error - check mfs_ferror for error code
*/
int MFSAPI mfs_fseeko(MFS_FILE *stream, off_t offset, int whence);

/* mfs_fileno
 *  Purpose: examines the argument stream and returns its integer descriptor (see c++ fileno documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
*     int  -  a file descriptor, nonnegative integer or -1 if an error occurred
*/
int MFSAPI mfs_fileno(MFS_FILE *stream);

/* mfs_fopen
 *  Purpose: open existing file or create a new one (see c++ fopen documentation for more details).
 *
 *  Parameters:
 *      filename - [IN] the name of the file to open/create. the format like following format:
 *         [for local file] /tmp/tmpfile                
 *         [for Amazon S3 protocol] s3://yourak:yoursk@xxxx.com/path1/name1	
 *         [for NFS protocol] nfs://user:pass@xxxx.com/path2/name2 
 *      flags - [IN] open flag. the meaning of these flags is exactly as specified in open().
 *  Parameters:
 *      mode - [IN] open mode. only supports 'r' or 'w' or 'a' (one and only one of them must be present), and optionally 'b' and/or '+'.
 * 
 *  Note - now, support s3 format and local format
 * 
 *  Return value:
 *     MFS_FILE*  - pointer to the newly created file handle, NULL if an error occurred - check errno for the error code.
*/
MFS_FILE* MFSAPI mfs_fopen(const char* filename, const char* mode);

/* mfs_fwrite
 *  Purpose: write data to a file (see c++ fwrite documentation for more details).
 *
 *  Parameters:
 *      ptr - [IN] pointer to the input data buffer
 *      size - [IN] size of data block
 *      count - [IN] count of data blocks to write
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     size_t  - number of 'size' blocks written to the file, 0 in case of an error - check mfs_ferror for error code
*/
size_t MFSAPI mfs_fwrite(const void* ptr, size_t size,
	size_t count, MFS_FILE* stream);

/* mfs_fread
 *  Purpose: read data from a file (see c++ fread documentation for more details).
 *
 *  Parameters:
 *      ptr - [OUT] pointer to the output data buffer
 *      size - [IN] size of data block
 *      count - [IN] count of data blocks to write
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     size_t  - number of 'size' blocks read from the file, 0 in case of an error - check mfs_ferror for error code
*/
size_t MFSAPI mfs_fread(void* ptr, size_t size,
	size_t count, MFS_FILE* stream);

/* mfs_ftell
 *  Purpose: get the current value of the position indicator of the file (see c++ ftell documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     long  - the current value of the position indicator, -1 on error - check errno for the error code
*/
long MFSAPI mfs_ftell(MFS_FILE* stream);

/* mfs_ftello
 *  Purpose: get the current value of the position indicator of the file (see c++ ftell documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     off_t  - the current value of the position indicator, -1 on error - check errno for the error code
*/
off_t MFSAPI mfs_ftello(MFS_FILE* stream);

/* mfs_fflush
 *  Purpose: force actual write of all the cached data to the disk (see c++ fflush documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     int  - result, 0 on success, -1 in case of an error - check mfs_ferror for error code
*/
int MFSAPI mfs_fflush(MFS_FILE* stream);

/* mfs_ferror
 *  Purpose: get the latest operation error code (see c++ ferror documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     int  - the error code, 0 means no error, anything else is the latest operation error code
*/
int MFSAPI mfs_ferror(MFS_FILE* stream);

/* mfs_feof
 *  Purpose: did the file's position indicator hit the end of the file in a previous read operation (see c++ feof documentation for more details).
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     int  - 1 - end of file was reached, 0 - end of file wasn't reached
*/
int MFSAPI mfs_feof(MFS_FILE* stream);

/* mfs_clearerr
 *  Purpose: try to clear an error in the file status, also clears the end-of-file flag (see c++ clearerr documentation for more details).
 *           call mfs_ferror or mfs_feof after a call to this function to learn if it was successful or not
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *      none
*/
void MFSAPI mfs_clearerr(MFS_FILE* stream);

/* mfs_fclose
 *  Purpose: close an open file handle (see c++ fclose documentation for more details).
 *           after a call to this function, the handle is invalid even if an error is returned
 *
 *  Parameters:
 *      stream - [IN] the file handle (opened with mfs_fopen or mfs_fdopen)
 *
 *  Return value:
 *     int  - result, 0 - file was closed successfully, -1 - there were errors during the operation
*/
int MFSAPI mfs_fclose(MFS_FILE* stream);


#ifdef __cplusplus
}
#endif

#endif // _MULTIFS_INTERFACE_H_

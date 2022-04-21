/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
/* file open and close */
#include <fcntl.h>
#include <unistd.h>

/* maximum file size */
#define BUF_SIZE 1024

/*
argv[1] : option (encryption, decryption)
argv[2] : filename
argv[3] : algorithm
*/
int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	if(argc < 3)
		{
			printf("not enough args\n");
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			return 0;
		}
	
	/* Open file and read file if file exist */
	char buf[BUF_SIZE];
	int fd;
	fd = open(argv[2], O_RDONLY); // file open, read only
	if(fd > 0) // if file exist
		{
			read(fd, buf, BUF_SIZE); // file content to buffer
			close(fd);
		}
	else
		{
			printf("file open failed\n");
			return 0; // process terminated
		}
	// buffer content copied to op.params[0]
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = BUF_SIZE;
	op.params[1].value.a = 0; // encrypted random key

	memcpy(op.params[0].tmpref.buffer, buf, BUF_SIZE);

	if(strcmp(argv[1], "-e") == 0) // check argv[1]
		{
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 	&err_origin);
			/* save encrypted file */
			int fd;
			char *filename = strcat(argv[2], "_enc");
			fd = open(filename, O_WRONLY | O_CREAT | O_EXCL);
			int len = strlen(op.params[0].tmpref.buffer);
			write(fd, op.params[0].tmpref.buffer, len);
			close(fd);
			/* integer key to char */
			char char_key[2];
			sprintf(char_key, "%d", op.params[1].value.a);
			/* save encrypted key */
			int fd_key;
			char *filename_key = strcat(argv[2], "_key");
			fd_key = open(filename_key, O_WRONLY | O_CREAT | O_EXCL);
			int len_key = strlen(char_key);
			write(fd_key, char_key, len_key);
			close(fd_key);						
		}
	else if(strcmp(argv[1], "-d") == 0)
		{
			/* read key file */
			char key[3];
			int fd_enckey;
			fd_enckey = open(argv[3], O_RDONLY);
			if(fd_enckey > 0)
				{
					read(fd_enckey, key, 3);
					close(fd_enckey);
				}
			else
				{
					printf("key read failed\n");
					return 0;
				}
			op.params[1].value.a = atoi(key);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
			/* save decrypted file */
			int fd_dec;
			char * filename_dec = strcat(argv[2], "_dec");
			fd_dec = open(filename_dec, O_WRONLY | O_CREAT | O_EXCL);
			int len_dec = strlen(op.params[0].tmpref.buffer);
			write(fd_dec, op.params[0].tmpref.buffer, len_dec);
			close(fd_dec);
		}
	else
		{
			printf("wrong arg\n");
			return 0;
		}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}

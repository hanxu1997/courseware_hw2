/* MDDRIVER.C - test driver for MD2, MD4 and MD5
*/

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
rights reserved.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
*/

/* The following makes MD default to MD5 if it has not already been
defined with C compiler flags.
*/
#ifndef MD
#define MD 5
#endif

#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include <ctime>
#include <cstring>
#include <cmath>
#include "global.hpp"
#include "md5.hpp"


/* Length of test block, number of test blocks.
*/
#define TEST_BLOCK_LEN 1000
#define TEST_BLOCK_COUNT 1000
#define WORD_LENGTH 4


static void MDString(char *);
static void MDTimeTrial(void);
static void MDTestSuite(void);
static void MDFile(char *);
static void MDFilter(void);
static void MDPrint(unsigned char[16]);
static void Menu(void);

#define MD_CTX MD5_CTX
#define MDInit MD5Init
#define MDUpdate MD5Update
#define MDFinal MD5Final

/* Main driver.

Arguments (may be any combination):
-s string - digests string
-t        - runs time trial
-x        - runs test script
filename  - digests file
(none)    - digests standard input
-h		  - print the menu
*/
int main(int argc, char *argv[]) {
	/*argc记录参数个数*/
	if (argc > 1) {   
		/* argv[0]指向的是 md5.exe */
		if (strcmp(argv[1], "-s") == 0) {
			if (argc == 3) {
				MDString(argv[2]);
			} else {
				MDString("");
			}
		} else if (strcmp(argv[1], "-t") == 0) {
			MDTimeTrial();
		} else if (strcmp(argv[1], "-x") == 0) {
			MDTestSuite();
		} else if (strcmp(argv[1], "-h") == 0) {
			Menu();
		} else {
			MDFile(argv[1]);
		}
	} else {
		MDFilter();
	}
	return 0;
}

/* show menu
*/
static void Menu(void)
{
	printf("menu:\n");
	printf("-s string - digests string\n"
		"-t        - runs time trial\n"
		"-x        - runs test script\n"
		"-h        - print help info\n"
		"filename  - digests file\n"
		"(none)    - digests standard input\n");
	return;
}

/* Digests a string and prints the result.
*/
static void MDString(char *string)
{
	MD_CTX context;
	unsigned char digest[16];
	unsigned int len = strlen((char *)string);

	MDInit(&context);
	MDUpdate(&context, (unsigned char *)string, len);
	MDFinal(digest, &context);

	printf("MD%d(%s) = ", MD, string);
	MDPrint(digest);
	printf("\n");
}

/* Measures the time to digest TEST_BLOCK_COUNT TEST_BLOCK_LEN-byte
blocks.
*/
static void MDTimeTrial()
{
	MD_CTX context;
	time_t endTime, startTime;
	unsigned char block[TEST_BLOCK_LEN], digest[16];
	unsigned int i;
	printf("MD%d time trial. Digesting %d %d-byte blocks ...", MD, TEST_BLOCK_LEN, TEST_BLOCK_COUNT);

	/* Initialize block */
	for (i = 0; i < TEST_BLOCK_LEN; i++)
	{
		block[i] = (unsigned char)(i & 0xff);
	}

	/* Start timer */
	time(&startTime);

	/* Digest blocks */
	MDInit(&context);
	for (i = 0; i < TEST_BLOCK_COUNT; i++)
	{
		MDUpdate(&context, block, TEST_BLOCK_LEN);
	}
	MDFinal(digest, &context);

	Sleep(2000);
	/* Stop timer */
	time(&endTime);

	printf(" done\n");
	printf("Digest = ");
	MDPrint(digest);
	printf("\nTime = %ld seconds\n", (long)(endTime - startTime));
	printf("Speed = %ld bytes/second\n", (long)TEST_BLOCK_LEN * (long)TEST_BLOCK_COUNT / (endTime - startTime));
}



/* Digests a reference suite of strings and prints the results.
*/
static void MDTestSuite()
{
	printf("MD%d test suite: ", MD);

	MDString("");
	MDString("a");
	MDString("abc");
	MDString("message digest");
	MDString("abcdefghijklmnopqrstuvwxyz");
	MDString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
	MDString("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

/* Digests a file and prints the result.
*/
static void MDFile(char *filename)
{
	FILE *file;
	MD_CTX context;
	int len;
	unsigned char buffer[1024], digest[16];

	if ((file = fopen(filename, "rb")) == NULL)
		printf("%s can't be opened\n", filename);
	else {
		MDInit(&context);
		while (len = fread(buffer, 1, 1024, file))
			MDUpdate(&context, buffer, len);
		MDFinal(digest, &context);

		fclose(file);

		printf("MD%d (%s) = ", MD, filename);
		MDPrint(digest);
		printf("\n");
	}
}

/* Digests the standard input and prints the result.
*/
static void MDFilter()
{
	MD_CTX context;
	size_t len = 0;
	unsigned char buffer[128] = {0}, digest[16] = {0};

	printf("Input:\n");

	MDInit(&context);

	if (fgets((char *)buffer, 128, stdin) != NULL) {
		len = strlen((char *)buffer);
		buffer[len - 1] = '\0'; // 尾部换行符去除
		len--;
	}
	else {
		return;
	}
		

	MDUpdate(&context, buffer, len);
	MDFinal(digest, &context);

	printf("MD5(%s) = ", buffer);
	MDPrint(digest);
	printf("\n");
}


/* Prints a message digest in hexadecimal.
*/
static void MDPrint(unsigned char digest[16])
{
	unsigned int i;
	for (i = 0; i < 16; i++)
		printf("%02x", digest[i]);
}



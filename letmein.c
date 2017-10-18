#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "cJSON.h"
#include "cJSON.c"

#define KEYLEN 16

/* store len bytes of entropy in arr */
void get_random_bytes(unsigned char *arr, int len)
{
	FILE *ivfile = fopen("iv.txt", "wb");
	int fd = open("/dev/urandom", O_RDONLY);
	read(fd, arr, len);
	fwrite(arr, 1, len, ivfile);
	fclose(ivfile);
	close(fd);
}

void get_iv(unsigned char *arr, int len)
{
	FILE *ivfile = fopen("iv.txt", "r");
	fread(arr, 1, len, ivfile);
	fclose(ivfile);
}

/* Gets unsalted hash from password *pass, returns key in *key */
void key_from_password(char *pass, int passlen, unsigned char *key)
{
	PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, NULL, 0, 10000, KEYLEN, key);
}

// do_encrypt -> 1 = encryption, 0 = decryption
// writes the decrypted contents to *out
int do_crypt(FILE *in, FILE *outfile, char *out, int do_encrypt,
	     unsigned char *key)
{
	/* Allow enough space in output buffer for additional block */
	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
	EVP_CIPHER_CTX ctx;

	unsigned char iv[KEYLEN];

	if (do_encrypt == 0)
		get_iv(iv, sizeof(iv));
	else if (do_encrypt == 1)
		get_random_bytes(iv, sizeof(iv));
	else
		exit(1);
		
	/* Don't set key or IV right away; we want to check lengths */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
			do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

	/* Now we can set key and IV */
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

	for(;;) 
	{
		inlen = fread(inbuf, 1, 1024, in);
		if(inlen <= 0)
			break;
		if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
		{
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		if (do_encrypt == 1)
			fwrite(outbuf, 1, outlen, outfile);
		else
			memcpy(out, outbuf, outlen);
	}
	int lenbefore = outlen;
	if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
	{
		/* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	if (do_encrypt == 1) {
		fwrite(outbuf, 1, outlen, outfile);
	} else {
		memcpy(out + lenbefore, outbuf, outlen);
		out[lenbefore + outlen + 1] = '\0';
	}

	EVP_CIPHER_CTX_cleanup(&ctx);
	return 1;
}

void print_usage()
{
	printf("Usage:\n" \
		"\t./letmein [-e/-d] infile outfile\n"
		"-e: encrypt\n"
		"-d: decrypt\n");
}

/*void parse_args(char *argv[], FILE *in, FILE *out)*/
/*{*/
	/*char *opt = argv[1];*/
	/*char *infile = argv[2];*/
	/*char *outfile = argv[3];*/

	/*in = fopen(infile, "r");*/
	/*out = fopen(outfile, "wb");*/
	
	/*if (!strcmp(opt, "-e")) {*/
		/*do_crypt(in, out, 1, key);*/
	/*} else if (!strcmp(opt, "-d")) {*/
		/*do_crypt(in, out, 0, key);*/
	/*}*/
/*}*/

void read_passwd(char *pass, int len)
{
	printf("Enter password:\n");
	fgets(pass, len, stdin);
}

char *read_file(FILE *fp)
{
	char *buf;
	long len;

	if (!fp) {
		perror("shadow.temp");
		exit(1);
	}

	fseek(fp, 0L, SEEK_END);
	len = ftell(fp);
	rewind(fp);

	buf = calloc(1, len + 1);
	if (!buf) {
		fclose(fp);
		fputs("malloc fail", stderr);
		exit(1);
	}

	if (fread(buf, len, 1, fp) != 1) {
		fclose(fp);
		free(buf);
		fputs("read fail", stderr);
		exit(1);
	}
	fclose(fp);
	return buf;
}

// add iv (initialization vector), random data
int main(int argc, char *argv[])
{
	/*if (argc < 4) {*/
		/*print_usage();*/
		/*exit(1);*/
	/*}*/

	char pass[40];
	unsigned char key[16];
	read_passwd(pass, sizeof(pass));
	key_from_password(pass, strlen(pass), key);

	FILE *passfile = fopen("shadow.letmein", "r");
	char buf[4096];

	do_crypt(passfile, NULL, buf, 0, key);

	fclose(passfile);

	cJSON *root = cJSON_Parse(buf);
	printf("%s\n", cJSON_Print(root));

	/*parse_args(argv, in, out);*/

	cJSON_Delete(root);
}

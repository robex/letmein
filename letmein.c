#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

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

void get_crypt_entropy(unsigned char *arr, int len)
{
	printf("Enter 16 random chars for password entropy generation\n");
	fgets((char*)arr, len, stdin);
}

/* Gets unsalted hash from password *pass, returns key in *key */
void key_from_password(char *pass, int passlen, unsigned char *key)
{
	PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, NULL, 0, 10000, KEYLEN, key);
}

// do_encrypt -> 1 = encryption, 0 = decryption
int do_crypt(FILE *in, FILE *out, int do_encrypt, unsigned char *key)
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
		
	/*get_crypt_entropy(iv, sizeof(iv));*/

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
		if(inlen <= 0) break;
		if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
		{
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		fwrite(outbuf, 1, outlen, out);
	}
	if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
	{
		/* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	fwrite(outbuf, 1, outlen, out);

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

// add iv (initialization vector), random data
int main(int argc, char *argv[])
{
	if (argc < 4) {
		print_usage();
		exit(1);
	}

	char *opt = argv[1];
	char *infile = argv[2];
	char *outfile = argv[3];

	char pass[40];
	unsigned char key[16];
	printf("Enter password:\n");
	fgets(pass, sizeof(pass), stdin);
	key_from_password(pass, strlen(pass), key);

	FILE *in = fopen(infile, "r");
	FILE *out = fopen(outfile, "wb");

	if (!strcmp(opt, "-e")) {
		do_crypt(in, out, 1, key);
	} else if (!strcmp(opt, "-d")) {
		do_crypt(in, out, 0, key);
	}
	fclose(in);
	fclose(out);
}

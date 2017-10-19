#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "json/cJSON.h"
#include "json/cJSON.c"

#define KEYLEN 16
#define IV_HEADER_SIZE 33	// 32 + newline
#define HASH_HEADER_SIZE 33
#define NWORDS 5

/* Splits the given null-terminated string str[] by the spaces.
 * The resulting words are stored in splits[]. Returns the # of words */
int splitstring(char *str, char *splits[], int len)
{
	int i = 1;
	if ((splits[0] = strtok(str, " \n\t")) == NULL)
		return 0;
	//check i < NWORDS to prevent out-of-bounds (*splits[NWORDS])
	while (((splits[i] = strtok(NULL, " \n\t")) != NULL) && (i < len)) {
		i++;
	}
	return i;
}

/* store len bytes of entropy in arr */
void get_random_bytes(unsigned char *arr, int len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	read(fd, arr, len);
	close(fd);
}

/* read initialization vector into string arr */
void get_iv(char *filename, unsigned char *arr, int len)
{
	char   hexiv[len*2];
	char   *pos = hexiv;
	FILE   *ivfile = fopen(filename, "r");

	fread(hexiv, 1, len*2, ivfile);
	fclose(ivfile);

	// translate from hex string back to char array
	for(size_t count = 0; count < KEYLEN; count++) {
		sscanf(pos, "%2hhx", &arr[count]);
		pos += 2;
	}
}

/* Gets unsalted hash from password *pass, returns key in *key */
void key_from_password(char *pass, int passlen, unsigned char *key)
{
	PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, NULL, 0, 10000, KEYLEN, key);
}

// do_encrypt -> 1 = encryption, 0 = decryption
// writes the decrypted contents to *out
int do_crypt(FILE *infile, char *in, FILE *outfile, char *out,
	     int do_encrypt, unsigned char *key, unsigned char *iv)
{
	/* Allow enough space in output buffer for additional block */
	unsigned char  inbuf[1024];
	unsigned char  outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int 	       inlen;
	int	       outlen;
	EVP_CIPHER_CTX ctx;
		
	/* Don't set key or IV right away; we want to check lengths */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
			do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

	/* Now we can set key and IV */
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

	int offset = 0;

	for(;;) 
	{
		if (do_encrypt == 1) {
			inlen = strnlen(in + offset, 1024);
			memcpy(inbuf, in + offset, inlen);
			offset += 1024;
		} else {
			inlen = fread(inbuf, 1, 1024, infile);
		}

		if(inlen <= 0)
			break;
		if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
		{
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		// if encrypting write to file, else write to string out
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
		"\t./letmein\n"
		"-e: encrypt\n"
		"-d: decrypt\n");
}

void read_passwd(char *pass, int len)
{
	printf("Enter password:\n");
	fgets(pass, len, stdin);
}

/* Reads entire file fp and returns the contents in a heap-allocated
 * char pointer */
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

/* Creates a password storage file filename, consisting of the
 * hash (in hex) and the json data */
void create_pass_file(char *filename)
{
	char data_json[1024];

	char pass[40];
	unsigned char key[KEYLEN];
	unsigned char iv[KEYLEN];
	
	get_random_bytes(iv, sizeof(iv));
	read_passwd(pass, sizeof(pass));
	key_from_password(pass, strlen(pass), key);

	// convert key and iv to hex
	unsigned char key_hex[32];
	unsigned char iv_hex[33];
	for (int i = 0; i < 16; i++)
		sprintf((char*)key_hex + i*2, "%02x", key[i]);
	for (int i = 0; i < 16; i++)
		sprintf((char*)iv_hex + i*2, "%02x", iv[i]);

	iv_hex[32] = '\n';

	// copy key to beginning of data_json
	memcpy(data_json, key_hex, sizeof(key_hex));
	// add newline after the key
	data_json[sizeof(key_hex)] = '\n';

	cJSON *root;
	root = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "site", cJSON_CreateString("fc.com"));
	char *json = cJSON_Print(root);

	// copy json string after the 0xKey
	memcpy(data_json + sizeof(key_hex) + 1, json, strlen(json) + 1);
	/*printf("%s\n", data_json);*/

	FILE *passfile = fopen(filename, "wb");
	// add iv_hex to beginning of file, dont encrypt in
	fwrite(iv_hex, 1, sizeof(iv_hex), passfile);
	// set the file pointer after the iv
	fseek(passfile, 32 + 1, 0);

	do_crypt(NULL, data_json, passfile, NULL, 1, key, iv);
	// dont forget to clean up!
	cJSON_Delete(root);
	fclose(passfile);
}

/* Decrypt and print the contents of file *filename */
void print_decrypt(char *filename)
{
	unsigned char key[KEYLEN];
	unsigned char iv[KEYLEN];
	FILE 	      *f = fopen(filename, "r");
	char	      decr_file[2048];
	char	      pass[40];

	read_passwd(pass, sizeof(pass));
	key_from_password(pass, strlen(pass), key);
	get_iv(filename, iv, sizeof(iv));
	// set the file pointer after the (plaintext) iv header
	fseek(f, IV_HEADER_SIZE, 0);
	do_crypt(f, NULL, NULL, decr_file, 0, key, iv);

	printf("file: %s\n", decr_file);
	fclose(f);
}

void parse_insert(char *args[], int nstr)
{
	char filename[40];
	sprintf(filename, "%s.letmein", args[0]);
	create_pass_file(filename);
}

void parse_list(char *args[], int nstr)
{
	char filename[40];
	sprintf(filename, "%s.letmein", args[0]);
	print_decrypt(filename);
}

void parse_arg(char *splits[], int nstr, short *quitshell)
{
	if (nstr > 0) {
		if (!strcmp(splits[0], "q") || !strcmp(splits[0], "quit")) {
			*quitshell = 1;
			exit(1);
		} else if (!strcmp(splits[0], "help")) {
			//TODO: parse help
			printf("dunno man, read the manual\n");
		} else if (!strcmp(splits[0], "insert")) {
			parse_insert(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "list")) {
			parse_list(splits + 1, nstr - 1);
		} else {
			printf("Unknown command. Type help for a list of "
			       "commands.\n");
		}
	}
}

int main(int argc, char *argv[])
{
	short quit = 0;
	char  buffer[64];
	char  *splits[NWORDS];
	int   nstr;

	while (!quit) {
		printf("> ");
		fgets(buffer, sizeof(buffer), stdin);

		nstr = splitstring(buffer, splits, NWORDS);
		parse_arg(splits, nstr, &quit);
	}
}

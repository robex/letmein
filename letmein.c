#include <stdio.h>
#include "letmein.h"

int  FILE_OPEN = 0;	// is passwd file open
char OPEN_FILENAME[64]; // filename
char *openfile;
cJSON *openfile_json_root;

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

/* Read password without echoing, storing it in lineptr (must
 * be heap-allocated) */
ssize_t get_pass(char **lineptr, size_t *n, FILE *stream)
{
	struct termios old, new;
	int 	       nread;

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr(fileno(stream), &old) != 0)
		return -1;
	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stream), TCSAFLUSH, &new) != 0)
		return -1;

	/* Read the password. */
	nread = getline(lineptr, n, stream);
	printf("\n");

	/* Restore terminal. */
	(void)tcsetattr(fileno (stream), TCSAFLUSH, &old);

	return nread;
}

/* Store len bytes of entropy in arr */
void get_random_bytes(unsigned char *arr, int len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	read(fd, arr, len);
	close(fd);
}

/* Read initialization vector into string arr */
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

/* Convert key[len] into hex string */
void char_to_hex(unsigned char *key, unsigned char *key_hex, int len)
{
	for (int i = 0; i < len; i++)
		sprintf((char*)key_hex + i*2, "%02x", key[i]);
}

/* Creates a password storage file filename, consisting of the
 * hash (in hex) and the json data */
void create_pass_file(char *filename)
{
	unsigned char key[KEYLEN];
	unsigned char iv[KEYLEN];
	char 	      data_json[1024];
	char 	      *pass;
	size_t	      passlen = 40;

	// file exists
	if (access(filename, F_OK) != -1) {
		printf("fatal: file %s already exists\n", filename);
		return;
	}
	
	pass = malloc(passlen * sizeof(char));
	get_random_bytes(iv, sizeof(iv));
	printf("Enter password: ");
	get_pass(&pass, &passlen, stdin);
	// newline after no-echo passwd input
	printf("\n");
	key_from_password(pass, strlen(pass), key);
	free(pass);

	// convert key and iv to hex
	unsigned char key_hex[32];
	unsigned char iv_hex[33];

	char_to_hex(key, key_hex, KEYLEN);
	char_to_hex(iv, iv_hex, KEYLEN);

	iv_hex[32] = '\n';

	// copy key to beginning of data_json
	memcpy(data_json, key_hex, sizeof(key_hex));
	// add newline after the key
	data_json[sizeof(key_hex)] = '\n';

	cJSON *root;
	// create empty json object
	root = cJSON_CreateObject();
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

/* Decrypt and return the contents of file *filename
 * Return 1 on succesful decrypt, 0 otherwise */
int decrypt_file(char *filename, char *decrstr)
{
	unsigned char key[KEYLEN];
	unsigned char iv[KEYLEN];
	unsigned char key_hex[2 * KEYLEN];
	FILE 	      *f = fopen(filename, "r");
	char	      *pass;
	size_t	      passlen = 40;

	// file does not exist
	if (access(filename, F_OK) == -1)
		return 2;

	pass = malloc(passlen * sizeof(char));
	printf("Enter password: ");
	get_pass(&pass, &passlen, stdin);
	key_from_password(pass, strlen(pass), key);
	free(pass);
	get_iv(filename, iv, sizeof(iv));
	char_to_hex(key, key_hex, KEYLEN);
	// set the file pointer after the (plaintext) iv header
	fseek(f, IV_HEADER_SIZE, 0);
	do_crypt(f, NULL, NULL, decrstr, 0, key, iv);

	fclose(f);

	// compare inputted key with decrypted one, stored in the file
	if (memcmp(key_hex, decrstr, KEYLEN * 2) == 0)
		return 1;
	else
		return 0;
}

void read_no_newline(char *buf, int len)
{
	fgets(buf, len, stdin);
	buf[strcspn(buf, "\n")] = 0;
}

int add_new(char *args[], int nstr)
{
	char   title[64];
	char   site_url[64];
	char   *passwd;
	char   *passwd_repeat;
	size_t passlen = 40;
	char   username[64];
	char   email[64];
	char   notes[256];

	// no file is open
	if (!FILE_OPEN) {
		printf("fatal: no open file.\n");
		return 0;
	}

	printf("Title: ");
	read_no_newline(title, sizeof(title));
	printf("Username: ");
	read_no_newline(username, sizeof(username));
	printf("Password: ");
	passwd = malloc(passlen * sizeof(char));
	passwd_repeat = malloc(passlen * sizeof(char));
	get_pass(&passwd, &passlen, stdin);
	passwd[strcspn(passwd, "\n")] = 0;
	printf("Repeat password: ");
	get_pass(&passwd_repeat, &passlen, stdin);
	passwd_repeat[strcspn(passwd_repeat, "\n")] = 0;
	// passwords are different
	if (strcmp(passwd, passwd_repeat)) {
		printf("Passwords do not match. Aborting...\n");
		free(passwd);
		free(passwd_repeat);
		return 0;
	}
	printf("URL: ");
	read_no_newline(site_url, sizeof(site_url));
	printf("Email: ");
	read_no_newline(email, sizeof(email));
	printf("Notes: ");
	read_no_newline(notes, sizeof(notes));
	
	cJSON *entry = cJSON_CreateObject();
	cJSON_AddItemToObject(openfile_json_root, title, entry);
	cJSON_AddStringToObject(entry, "username", username);
	cJSON_AddStringToObject(entry, "site_url", site_url);
	cJSON_AddStringToObject(entry, "passwd", passwd);
	cJSON_AddStringToObject(entry, "email", email);
	cJSON_AddStringToObject(entry, "notes", notes);

	printf("%s\n", cJSON_Print(openfile_json_root));
	free(passwd);
	free(passwd_repeat);
	return 1;
}

void parse_insert(char *args[], int nstr)
{
	char filename[40];
	sprintf(filename, "%s.letmein", args[0]);
	create_pass_file(filename);
}

void parse_open(char *args[], int nstr)
{
	char filename[40];
	int  status;
	sprintf(filename, "%s.letmein", args[0]);
	openfile = malloc(2048 * sizeof(char));
	status = decrypt_file(filename, openfile);
	if (status == 1) {
		FILE_OPEN = 1;
		strcpy(OPEN_FILENAME, filename);
		openfile_json_root = cJSON_Parse(openfile + IV_HEADER_SIZE);
		printf("Opened file %s\n", OPEN_FILENAME);
	} else if (status == 0) {
		printf("%s: Invalid password\n", filename);
		free(openfile);
	} else if (status == 2) {
		printf("fatal: file %s doesn't exist\n", filename);
		free(openfile);
	}
}

void parse_add(char *args[], int nstr)
{
	add_new(args, nstr);
}

void print_usage()
{
	printf("Usage:\n" \
		"\tnew [file]: create new password file\n"
		"\topen [file]: load password file\n"
		"\tq(uit): exit the program\n");
}

void parse_arg(char *splits[], int nstr, short *quitshell)
{
	if (nstr > 0) {
		if (!strcmp(splits[0], "q") || !strcmp(splits[0], "quit")) {
			*quitshell = 1;
		} else if (!strcmp(splits[0], "help")) {
			//TODO: parse help
			print_usage();
		} else if (!strcmp(splits[0], "new")) {
			parse_insert(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "open")) {
			parse_open(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "add")) {
			parse_add(splits + 1, nstr - 1);
		} else {
			printf("Unknown command. Type 'help' for a list of "
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

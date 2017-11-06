#include <stdio.h>
#include "letmein.h"

int  IS_FILE_OPEN = 0;	// is passwd file open
char OPEN_FILENAME[64]; // filename
char *openfile;
cJSON *ROOT;

struct help_cmds help = {
	{
		"help",
		"new",
		"open",
		"save",
		"close",
		"add",
		"show",
		"rm",
		"edit",
		"q", "quit",
	}, {
		"help [cmd]: show help of command cmd",
		"new [file]: create a new password file [file].letmein",
		"open [file]: load the password file [file].letmein",
		"save: save the changes in the current password file",
		"close: close the current password file",
		"add: add a new entry to the current password file",
		"show [entry]: show all the entry titles\n"
			"\t if [entry] is specified, show the whole entry",
		"rm [entry]: delete the specified entry",
		"edit [entry] [field]: edit the specified field of entry\n"
			"\t field names are: title, username, site_url, "
			"passwd, email, notes",
		"q(uit): exit the program",
		"q(uit): exit the program",
	}
};
	

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

int sure()
{
	char opt;
	printf("Are you sure? y/n: ");
	if ((opt = getchar()) == 'y')
		return 1;
	else 
		return 0;
}

/* Read password without echoing, storing it in lineptr (must
 * be heap-allocated) */
ssize_t get_pass_raw(char **lineptr, size_t *n, FILE *stream)
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

/* Translate from hex string back to char array */
void hex_to_char(char *hex, unsigned char *raw)
{
	char *pos = hex;
	for(size_t count = 0; count < KEYLEN; count++) {
		sscanf(pos, "%2hhx", &raw[count]);
		pos += 2;
	}
}

/* Convert key[len] into hex string */
void char_to_hex(unsigned char *key, unsigned char *key_hex, int len)
{
	for (int i = 0; i < len; i++)
		sprintf((char*)key_hex + i*2, "%02x", key[i]);
}

/* Read initialization vector into string arr
 * hex -> 0: return raw, 1: hex string*/
void get_iv(char *filename, unsigned char *arr, int hex)
{
	char   hexiv[KEYLEN * 2];
	FILE   *ivfile = fopen(filename, "r");

	fread(hexiv, 1, KEYLEN * 2, ivfile);
	fclose(ivfile);

	if (hex)
		arr = (unsigned char*)hexiv;
	else
		hex_to_char(hexiv, arr);
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
	get_pass_raw(&pass, &passlen, stdin);
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
	cJSON *entries;
	// create empty json object
	root = cJSON_CreateObject();
	entries = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "entries", entries);
	
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
	get_pass_raw(&pass, &passlen, stdin);
	key_from_password(pass, strlen(pass), key);
	free(pass);
	get_iv(filename, iv, 0);
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

/* Read string into buf and strip newline */
void read_no_newline(char *buf, int len)
{
	fgets(buf, len, stdin);
	buf[strcspn(buf, "\n")] = 0;
}

/* Prompt, check and store in passwd a password without echoing */
int get_pass_str(char **passwd)
{
	char   *passwd_repeat;
	size_t passlen = 40;

	printf("Password: ");
	*passwd = malloc(passlen * sizeof(char));
	passwd_repeat = malloc(passlen * sizeof(char));
	get_pass_raw(&(*passwd), &passlen, stdin);
	(*passwd)[strcspn(*passwd, "\n")] = 0;
	printf("Repeat password: ");
	get_pass_raw(&passwd_repeat, &passlen, stdin);
	passwd_repeat[strcspn(passwd_repeat, "\n")] = 0;
	// passwords are different
	if (strcmp(*passwd, passwd_repeat)) {
		printf("Passwords do not match. Aborting...\n");
		free(*passwd);
		free(passwd_repeat);
		return 0;
	}
	free(passwd_repeat);
	return 1;
}

/* Prompt to add a new user to file */
int add_new(char *args[], int nstr)
{
	char   title[64];
	char   site_url[64];
	char   *passwd = NULL;
	char   username[64];
	char   email[64];
	char   notes[256];

	// no file is open
	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return 0;
	}

	printf("Title: ");
	read_no_newline(title, sizeof(title));
	printf("Username: ");
	read_no_newline(username, sizeof(username));
	printf("URL: ");
	read_no_newline(site_url, sizeof(site_url));
	if (!get_pass_str(&passwd))
		return 0;
	printf("Email: ");
	read_no_newline(email, sizeof(email));
	printf("Notes: ");
	read_no_newline(notes, sizeof(notes));
	
	cJSON *entries = cJSON_GetObjectItem(ROOT, "entries");
	cJSON *entry = cJSON_CreateObject();
	cJSON_AddStringToObject(entry, "title", title);
	cJSON_AddStringToObject(entry, "username", username);
	cJSON_AddStringToObject(entry, "site_url", site_url);
	cJSON_AddStringToObject(entry, "passwd", passwd);
	cJSON_AddStringToObject(entry, "email", email);
	cJSON_AddStringToObject(entry, "notes", notes);

	cJSON_AddItemToArray(entries, entry);

	printf("Succesfully added entry %s\n", title);

	/*printf("%s\n", cJSON_Print(ROOT));*/
	free(passwd);
	return 1;
}

void parse_new(char *args[], int nstr)
{
	char filename[40];
	if (args[0] == NULL) {
		printf("error: must pass a filename\n");
		return;
	}
	sprintf(filename, "%s.letmein", args[0]);
	create_pass_file(filename);
}

/* Open file *filename, loading the json */
void parse_open(char *args[], int nstr)
{
	char filename[40];
	int  status;
	sprintf(filename, "%s.letmein", args[0]);
	if (IS_FILE_OPEN) {
		printf("File already opened. Aborting...\n");
		return;
	}
		
	openfile = malloc(2048 * sizeof(char));
	status = decrypt_file(filename, openfile);
	if (status == 1) {
		IS_FILE_OPEN = 1;
		strcpy(OPEN_FILENAME, filename);
		ROOT = cJSON_Parse(openfile + IV_HEADER_SIZE);
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

/* Save current json file (overwrites) */
void parse_save(char *args[], int nstr)
{
	unsigned char key[KEYLEN];
	unsigned char iv[KEYLEN];
	unsigned char iv_hex[33];

	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return;
	}
	hex_to_char(openfile, key);
	get_iv(OPEN_FILENAME, iv, 0);
	char_to_hex(iv, iv_hex, sizeof(iv));
	iv_hex[32] = '\n';
	// reopen file
	FILE *f = fopen(OPEN_FILENAME, "w");
	// write the hex iv
	fwrite(iv_hex, 1, 33, f);
	fseek(f, 33, 0);
	// update openfile
	strcpy(openfile + IV_HEADER_SIZE, cJSON_Print(ROOT));
	do_crypt(NULL, openfile, f, NULL, 1, key, iv);
	fclose(f);
}

/* Show all the titles of the entries */
void show_all()
{
	cJSON *entries = cJSON_GetObjectItem(ROOT, "entries");
	for (int i = 0; i < cJSON_GetArraySize(entries); i++) {
		cJSON *entry = cJSON_GetArrayItem(entries, i);
		cJSON *title = cJSON_GetObjectItem(entry, "title");
		cJSON *url = cJSON_GetObjectItem(entry, "site_url");
		printf("- %s, ", title->valuestring);
		printf("%s\n", url->valuestring);
	}
}

/* Pretty print the entry *entry */
void show_print_entry(cJSON *entry)
{
	cJSON *subitem = cJSON_GetObjectItem(entry, "title");
	printf("\nTITLE: %s\n", subitem->valuestring); 
	printf("\tUsername: %s\n", subitem->next->valuestring);
	subitem = subitem->next;
	printf("\tURL: %s\n", subitem->next->valuestring);
	subitem = subitem->next;
	printf("\tPassword: %s\n", subitem->next->valuestring);
	subitem = subitem->next;
	printf("\tE-mail: %s\n", subitem->next->valuestring);
	subitem = subitem->next;
	printf("\tAdditional notes: %s\n\n", subitem->next->valuestring);
}

/* Get the entry with title entryname */
struct array_item show_get_entry(char *entryname)
{
	cJSON *entries = cJSON_GetObjectItem(ROOT, "entries");
	struct array_item item;
	item.entry = NULL;
	item.index = -1;

	for (int i = 0; i < cJSON_GetArraySize(entries); i++) {
		cJSON *entry = cJSON_GetArrayItem(entries, i);
		cJSON *title = cJSON_GetObjectItem(entry, "title");
		if (!strcmp(title->valuestring, entryname)) {
			item.entry = entry;
			item.index = i;
			return item;
		}
	}
	return item;
}

/* Parse arguments for the show command */
void parse_show(char *args[], int nstr)
{
	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return;
	} else if (args[0] == NULL) {
		show_all();
	// show entry passed as argument
	} else {
		struct array_item item = show_get_entry(args[0]);
			if (item.entry == NULL) {
				printf("error: entry %s not found\n",
				       args[0]);
				return;
			}
		show_print_entry(item.entry);
	}
}

/* Close the current file and free the buffers */
void close_file()
{
	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return;
	}
	cJSON_Delete(ROOT);
	free(openfile);
	strcpy(OPEN_FILENAME, "");
	IS_FILE_OPEN = 0;
}

/* Parse and print help command */
void help_print(char *arg)
{
	int i;
	int helplen = sizeof(help.help_names) / sizeof(help.help_names[0]);
	int found = 0;

	if (arg == NULL) {
		printf("Type help [cmd] for info about a command:\n");
		for (i = 0; i < helplen - 1; i++) {
			printf("%s, ", help.help_names[i]);
		}
		printf("%s\n", help.help_names[i]);
	} else {
		for (i = 0; i < helplen; i++) {
			if (!strcmp(help.help_names[i], arg)) {
				printf("%s\n", help.help_descs[i]);
				found = 1;
				break;
			}
		}
		if (!found)
			printf("help: cmd '%s' does not exist.\n", arg);
	}
}

/* Deletes entry entryname */
void rm_entry(char *entryname)
{
	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return;
	}
	struct array_item item = show_get_entry(entryname);

	// entry does not exist
	if (item.entry == NULL) {
		printf("error: entry %s not found\n", entryname);
		return;
	}
	if (!sure())
		return;
	cJSON *entries = cJSON_GetObjectItem(ROOT, "entries");
	cJSON_DetachItemFromArray(entries, item.index);
}

void parse_rm(char *args[], int nargs)
{
	if (args[0] == NULL)
		printf("error: must supply an entry name\n");
	else
		rm_entry(args[0]);
}

/* Edit the entry entryname, where field may be any of the json
 * key values */
void edit_entry(char *entryname, char *fieldname)
{
	// new value for the field
	char *value = NULL;

	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return;
	}
	struct array_item item = show_get_entry(entryname);

	// entry does not exist
	if (item.entry == NULL) {
		printf("error: entry %s not found\n", entryname);
		return;
	}

	// special case to edit the password
	if (!strcmp(fieldname, "passwd")) {
		if (!get_pass_str(&value))
			return;

	} else {
		value = malloc(64 * sizeof(char));
		printf("Enter new %s: ", fieldname);
		read_no_newline(value, 64);
	}
	
	cJSON *selected_field = cJSON_GetObjectItem(item.entry, fieldname);
	// release old value
	free(selected_field->valuestring);
	// allocate exact size for new string
	selected_field->valuestring = malloc(strlen(value));
	strcpy(selected_field->valuestring, value);
	free(value);
}

void parse_edit(char *args[], int nargs)
{
	if (args[0] == NULL || args[1] == NULL)
		printf("error: must specify an entry name and a field name\n");
	else
		edit_entry(args[0], args[1]);
}

/* Dump json of currently open file */
void print_debug()
{
	if (!IS_FILE_OPEN) {
		printf("fatal: file not open\n");
		return;
	} else {
		printf("%s\n", openfile); //debug
	}
}

void parse_arg(char *splits[], int nstr, short *quitshell)
{
	if (nstr > 0) {
		if (!strcmp(splits[0], "q") || !strcmp(splits[0], "quit")) {
			*quitshell = 1;
		} else if (!strcmp(splits[0], "help")) {
			help_print(splits[1]);
		} else if (!strcmp(splits[0], "new")) {
			parse_new(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "open")) {
			parse_open(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "save")) {
			parse_save(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "close")) {
			close_file();
		} else if (!strcmp(splits[0], "add")) {
			parse_add(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "rm")) {
			parse_rm(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "edit")) {
			parse_edit(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "show")) {
			parse_show(splits + 1, nstr - 1);
		} else if (!strcmp(splits[0], "print")) {
			print_debug();
		} else {
			printf("Unknown command. Type 'help' for a list of "
			       "commands.\n");
		}
	}
}

/* What a mess
 * TODO: If terminal is too small dont print it, center */
void print_banner()
{
	// clear the screen
	write(STDOUT_FILENO, "\x1b[2J", 4);
	// move cursor to first row and first col
	write(STDOUT_FILENO, "\x1b[H", 3);

	printf(
"	 ___           __                                      \n"
"	/\\_ \\         /\\ \\__                     __            \n"
"	\\//\\ \\      __\\ \\ ,_\\   ___ ___      __ /\\_\\    ___    \n"
"	  \\ \\ \\   /'__`\\ \\ \\/ /' __` __`\\  /'__`\\/\\ \\ /' _ `\\  \n"
"	   \\_\\ \\_/\\  __/\\ \\ \\_/\\ \\/\\ \\/\\ \\/\\  __/\\ \\ \\/\\ \\/\\ \\ \n"
"	   /\\____\\ \\____\\\\ \\__\\ \\_\\ \\_\\ \\_\\ \\____\\\\ \\_\\ \\_\\ \\_\\\n"
"	   \\/____/\\/____/ \\/__/\\/_/\\/_/\\/_/\\/____/ \\/_/\\/_/\\/_/\n"
	
	"\n                           by r0bex - 2017\n\n");
}

int main(int argc, char *argv[])
{
	short quit = 0;
	char  buffer[64];
	char  *splits[NWORDS];
	int   nstr;
	
	print_banner();
	while (!quit) {
		printf("> ");
		fgets(buffer, sizeof(buffer), stdin);

		nstr = splitstring(buffer, splits, NWORDS);
		parse_arg(splits, nstr, &quit);
	}
}

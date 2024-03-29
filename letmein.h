#include <string.h>
#include <termios.h>
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

struct help_cmds {
	char *help_names[11];
	char *help_descs[11];
};

struct array_item {
	cJSON *entry;
	int index;
};

/* Splits the given null-terminated string str[] by the spaces.
 * The resulting words are stored in splits[]. Returns the # of words */
int splitstring(char *str, char *splits[], int len);
/* Read password without echoing, storing it in lineptr (must
 * be heap-allocated) */
ssize_t get_pass_raw(char **lineptr, size_t *n, FILE *stream);
/* Store len bytes of entropy in arr */
void get_random_bytes(unsigned char *arr, int len);
/* Translate from hex string back to char array */
void hex_to_char(char *hex, unsigned char *raw);
/* Convert key[len] into hex string */
void char_to_hex(unsigned char *key, unsigned char *key_hex, int len);
/* Read initialization vector into string arr */
void get_iv(char *filename, unsigned char *arr, int hex);
/* Gets unsalted hash from password *pass, returns key in *key */
void key_from_password(char *pass, int passlen, unsigned char *key);
// do_encrypt -> 1 = encryption, 0 = decryption
// writes the decrypted contents to *out
int do_crypt(FILE *infile, char *in, FILE *outfile, char *out,
	     int do_encrypt, unsigned char *key, unsigned char *iv);
/* Reads entire file fp and returns the contents in a heap-allocated
 * char pointer */
char *read_file(FILE *fp);
/* Creates a password storage file filename, consisting of the
 * hash (in hex) and the json data */
void create_pass_file(char *filename);
/* Decrypt and return the contents of file *filename
 * Return 1 on succesful decrypt, 0 otherwise */
int decrypt_file(char *filename, char *decrstr);
/* Read string into buf and strip newline */
void read_no_newline(char *buf, int len);
/* Prompt, check and store in passwd a password without echoing */
int get_pass_str(char **passwd);
/* Prompt to add a new user to file */
int add_new(char *args[], int nstr);
void parse_new(char *args[], int nstr);
/* Open file *filename, loading the json */
void parse_open(char *args[], int nstr);
void parse_add(char *args[], int nstr);
/* Save current json file (overwrites) */
void parse_save(char *args[], int nstr);
/* Show all the titles of the entries */
void show_all();
/* Pretty print the entry *entry */
void show_print_entry(cJSON *entry);
/* Get the entry with title entryname */
struct array_item show_get_entry(char *entryname);
/* Parse arguments for the show command */
void parse_show(char *args[], int nstr);
/* Close the current file and free the buffers */
void close_file();
/* Parse and print help command */
void help_print(char *arg);
/* Deletes entry entryname */
void rm_entry(char *entryname);
void parse_rm(char *args[], int nargs);
/* Edit the entry entryname, where field may be any of the json
 * key values */
void edit_entry(char *entryname, char *fieldname);
void parse_edit(char *args[], int nargs);
/* Dump json of currently open file */
void print_debug();
void parse_arg(char *splits[], int nstr, short *quitshell);
/* What a mess */
void print_banner();

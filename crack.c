#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/md5.h>
#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings (32 + NUL)
const int LINE_BUF = 4096;

/* helper: trim trailing newline / CR / spaces */
static void rtrim(char *s) {
    int n = (int)strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' || s[n-1] == ' ' || s[n-1] == '\t')) {
        s[--n] = '\0';
    }
}

/* helper: compute lowercase hex MD5 of `plaintext` into out (size >=33) */
static void md5_hex(const char *plaintext, char out[HASH_LEN]) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)plaintext, strlen(plaintext), digest);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(out + i*2, "%02x", digest[i]);
    }
    out[32] = '\0';
}


char * tryWord(char * plaintext, char * hashFilename)
{
    char myhash[HASH_LEN];
    md5_hex(plaintext, myhash);

    FILE *hf = fopen(hashFilename, "r");
    if (!hf) {
        fprintf(stderr, "Error: cannot open hash file '%s'\n", hashFilename);
        return NULL;
    }

    char line[LINE_BUF];
    while (fgets(line, sizeof(line), hf)) {
        rtrim(line);
        /* find the first 32 hex characters in the line (basic robustness) */
        char candidate[HASH_LEN];
        int j = 0;
        for (size_t i = 0; i < strlen(line) && j < 32; ++i) {
            if (isxdigit((unsigned char)line[i])) {
                candidate[j++] = (char)tolower((unsigned char)line[i]);
            }
        }
        if (j != 32) continue;
        candidate[32] = '\0';

        if (strcmp(candidate, myhash) == 0) {
            /* match found: return a malloc'd copy of the hash */
            char *ret = malloc(HASH_LEN);
            if (ret) strncpy(ret, candidate, HASH_LEN);
            fclose(hf);
            return ret;
        }
    }

    fclose(hf);
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    char *hashFile = argv[1];
    char *dictFile = argv[2];

    /* Test Case */
    // char *found = tryWord("hello", "hashes00.txt");
    // if (found) {
    //     printf("%s %s\n", found, "hello");
    //     free(found);
    // } else {
    //     printf("not found for hello (test)\n");
    // }

    
    FILE *df = fopen(dictFile, "r");
    if (!df) {
        fprintf(stderr, "Error: cannot open dictionary file '%s'\n", dictFile);
        exit(1);
    }

    size_t cracked = 0;
    char word[LINE_BUF];

    while (fgets(word, sizeof(word), df)) {
        rtrim(word);
        if (word[0] == '\0') continue;

        char *match = tryWord(word, hashFile);
        if (match) {
            printf("%s %s\n", match, word);
            free(match);
            cracked++;
        }
    }

    fclose(df);

    printf("%zu hashes cracked!\n", cracked);

    return 0;
}
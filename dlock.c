#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "SHA256.h"

#define KEY_SIZE 32
#define IV_SIZE 32


typedef struct data
{
    char passhash[300];
    char exthash[50];
}data;


char* en2(char *p)
{
    char ps[]="5732f4afcd23b";
    int plen=strlen(p);
    int pslen=strlen(ps);
    static char en2res[30];
    for(int i=0;i<plen;i++)
    {
        en2res[i]=p[i]^(ps[(i%pslen)]);
    }
    return en2res;
}

char* de2(char *p)
{
    char ps[]="5732f4afcd23b";
    int plen=strlen(p);
    int pslen=strlen(ps);
    static char de2res[30];
    for(int i=0;i<plen;i++)
    {
        de2res[i]=p[i]^(ps[(i%pslen)]);
    }
    return de2res;
}

char* generatePolymorphicString(const char* hash) {
    size_t hashLen = strlen(hash);
    size_t strLen = 2 * hashLen + 1;
    char* polymorphicStr = (char*)malloc(strLen * sizeof(char));

    for (size_t i = 0; i < hashLen; i++) {
        snprintf(&polymorphicStr[2 * i], 3, "%02x", (unsigned char)hash[i]);
    }
    polymorphicStr[strLen - 1] = '\0';

    return polymorphicStr;
}

char* retrieveHash(const char* polymorphicStr) {
    size_t strLen = strlen(polymorphicStr);
    size_t hashLen = strLen / 2;
    char* hash = (char*)malloc((hashLen + 1) * sizeof(char));

    for (size_t i = 0; i < hashLen; i++) {
        sscanf(&polymorphicStr[2 * i], "%2hhx", &hash[i]);
    }
    hash[hashLen] = '\0';

    return hash;
}


void encrypt_file(const char *input_file,const char *password)
{
    FILE *input_fp = fopen(input_file, "rb");
    if (input_fp == NULL)
    {
        perror("Error opening input file");
        exit(1);
    }

    int p,k=0;
    int inlen=strlen(input_file);//find len of infile name
    char output_file[100];
    char ext[15];
    char stack[15];
    int top=-1;
    for(p=inlen-1;p>=0;p--)
    {
        if(input_file[p]=='.')
        {
            stack[++top]=input_file[p];
            break;
        }
        stack[++top]=input_file[p];
    }                                           //extract ext
    while(top>-1)
        ext[k++]=stack[top--];
    ext[k]='\0';                                //ext came in ext

    //generaing output file name
    top=-1;
    stack[++top]='k';
    stack[++top]='c';
    stack[++top]='o';
    stack[++top]='l';
    while(p>=0)
        stack[++top]=input_file[p--];// got complete outFile name in stack
    //put in outputfile name
    k=0;
    while(top>=0)
        output_file[k++]=stack[top--];
    output_file[k]='\0';
    //done with it
    FILE *output_fp = fopen(output_file, "wb");
    if (output_fp == NULL)
    {
        perror("Error opening output file");
        exit(1);
    }

    //writing the things to structure 
    data d;
    char* polymorphicString = generatePolymorphicString(SHA256(password));
    strcpy(d.passhash,polymorphicString);
    strcpy(d.exthash,en2(ext));
    free(polymorphicString);//free dynamic memory
    //write structure to file
    fwrite(&d, sizeof(data), 1, output_fp);

    //continue with file encryption
    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    strncpy((char *)key, password, KEY_SIZE);
    strncpy((char *)iv, password + KEY_SIZE, IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Error creating encryption context");
        exit(1);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error initializing encryption");
        exit(1);
    }

    const int BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char cipher_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int len;
    int cipher_len;

    while ((len = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input_fp)) > 0)
    {
        if (EVP_EncryptUpdate(ctx, cipher_buffer, &cipher_len, buffer, len) != 1)
        {
            fprintf(stderr, "Error encrypting data");
            exit(1);
        }
        fwrite(cipher_buffer, sizeof(unsigned char), cipher_len, output_fp);
    }

    if (EVP_EncryptFinal_ex(ctx, cipher_buffer, &cipher_len) != 1)
    {
        fprintf(stderr, "Error finalizing encryption");
        exit(1);
    }
    fwrite(cipher_buffer, sizeof(unsigned char), cipher_len, output_fp);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_fp);
    fclose(output_fp);

    printf("Encryption complete: %s -> %s\n", input_file, output_file);
}

void decrypt_file(const char *input_file, const char *password)
{
    FILE *input_fp = fopen(input_file, "rb");
    if (input_fp == NULL)
    {
        perror("Error opening input file");
        exit(1);
    }

    //extract input file name without .lock
    char infilename[100];

    int inlen = strlen(input_file);
    if (inlen >= 5 && strcmp(input_file + inlen - 5, ".lock") == 0) 
    {
        strncpy(infilename, input_file, inlen - 5);
        infilename[inlen - 5] = '\0';
    }
    else 
    {
        printf("!Error: ");
        printf("The given input file is not .lock file\nDecryption failed\n");
        fclose(input_fp);
        exit(0);
    }

    char output_file[100];
    strcpy(output_file,infilename);

    //geting things ready for password verification
    char userpass[67];
    strcpy(userpass,SHA256(password));
    data d;
    fread(&d, sizeof(data), 1, input_fp);
    char* retrievedHash = retrieveHash(d.passhash);
    if(strcmp(retrievedHash,userpass)!=0)//Verify password
    {
        printf("Wrong password\n");
        fclose(input_fp);
        free(retrievedHash);
        exit(0);
    }
    free(retrievedHash);
    strcpy(d.exthash,de2(d.exthash));//decrypt extension
    strcat(output_file,d.exthash);
    //output file name is ready
    FILE *output_fp = fopen(output_file, "wb");
    if (output_fp == NULL)
    {
        perror("Error opening output file");
        exit(1);
    }

    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    strncpy((char *)key, password, KEY_SIZE);
    strncpy((char *)iv, password + KEY_SIZE, IV_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        fprintf(stderr, "Error creating decryption context");
        exit(1);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        fprintf(stderr, "Error initializing decryption");
        exit(1);
    }

    const int BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char plain_buffer[BUFFER_SIZE];
    int len;
    int plain_len;

    while ((len = fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input_fp)) > 0)
    {
        if (EVP_DecryptUpdate(ctx, plain_buffer, &plain_len, buffer, len) != 1)
        {
            fprintf(stderr, "Error decrypting data");
            exit(1);
        }
        fwrite(plain_buffer, sizeof(unsigned char), plain_len, output_fp);
    }

    if (EVP_DecryptFinal_ex(ctx, plain_buffer, &plain_len) != 1)
    {
        fprintf(stderr, "Error finalizing decryption");
        exit(1);
    }
    fwrite(plain_buffer, sizeof(unsigned char), plain_len, output_fp);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_fp);
    fclose(output_fp);

    printf("Decryption complete: %s -> %s\n", input_file, output_file);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s [lock|unlock] input_file password\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *input_file = argv[2];
    char hash[257];
    strcpy(hash, SHA256(argv[3]));
    const char *password = hash;

    OpenSSL_add_all_algorithms();

    if (strcmp(mode, "lock") == 0)
    {
        encrypt_file(input_file,password);
    }
    else if (strcmp(mode, "unlock") == 0)
    {
        decrypt_file(input_file,password);
    }
    else
    {
        printf("Invalid mode. Please use 'lock' or 'unlock'.\n");
        return 1;
    }

    return 0;
}

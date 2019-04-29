#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <sodium.h>
#include <string.h>
#include "state.h"
#include "cmd.h"
#include "csv.h"
#include "base64.h"

// Global values
#define DB "/.kind/db.csv"
#define KEY_LEN crypto_box_SEEDBYTES // crypto_secretbox_KEYBYTES
#define PWD_LEN 32
#define LINE_LEN 4096
#define URL_LEN 128

// Global variables
char *filename;
FILE *db;
enum state state;
unsigned char masterKey[crypto_secretbox_KEYBYTES];

void sigHandler(int signum){
    printf("Caught signal %d, exiting...\n", signum);
    exit(EXIT_FAILURE);
}

void init(){

    filename = getenv("HOME");
    strcat(filename, DB);

    state = LOCKED;

    // Initializing libsodium library
    if (sodium_init() < 0) {
        printf("Fatal error. Libsodium initialization failed. Exiting...");
        exit(EXIT_FAILURE);
    }

    // Registering a signal handler
    signal(SIGINT, sigHandler);
}

void help(){
    printf("\n");
    printf("[%d] EXI: exists the program. \n", EXI);
    printf("[%d] CLO: closes the database. \n", CLO);
    printf("[%d] ADD: adds a password. \n", ADD);
    printf("[%d] DEL: deletes a password. \n", DEL);
    printf("[%d] SHW: shows a password. \n", SHW);
    printf("[%d] CHP: changes the master password. \n", CHP);
    printf("[%d] LST: lists all passwords. \n", LST);
    printf("\n");
}

void createDB(){

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    char *encodedNonce;
    unsigned char encryptedMasterKey[crypto_secretbox_MACBYTES+sizeof(masterKey)];
    char *encodedEncryptedMasterKey;
    unsigned char derivedKey[KEY_LEN];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    char *encodedSalt;
    char hash[crypto_pwhash_STRBYTES];
    char *pwd;
    size_t eSaltLen, eNonceLen, eEncMasterKeyLen;

    printf("Database not found under %s. Creating a new one...\n", filename);

    // Generating a master key
    crypto_secretbox_keygen(masterKey);

    // Getting random values for nonce and salt
    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(salt, sizeof(salt));

    // Reading the password
    pwd = sodium_malloc(PWD_LEN);
    printf("Enter a master password: ");
    scanf("%s", pwd);
    // Hashing the password
    if(crypto_pwhash_str(hash, pwd, strlen(pwd), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0){
        sodium_free(pwd);
        printf("Fatal error. Program ran out ouf memory. Exiting...\n");
        exit(EXIT_FAILURE);
    }

    // Deriving a key to encrypt the master key
    if (crypto_pwhash(derivedKey, sizeof(derivedKey), pwd, strlen(pwd), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        sodium_free(pwd);
        printf("Fatal error. Program ran out ouf memory. Exiting...\n");
        exit(EXIT_FAILURE);
    }

    // We don't need the password anymore. Freeing memory
    sodium_memzero(pwd, PWD_LEN);

    // Encrypting the master key
    crypto_secretbox_easy(encryptedMasterKey, masterKey, sizeof(masterKey), nonce, derivedKey);

    // Encoding hash, salt and nonce
    encodedSalt = base64_encode(salt, sizeof(salt), &eSaltLen);
    encodedNonce = base64_encode(nonce, sizeof(nonce), &eNonceLen);
    encodedEncryptedMasterKey = base64_encode(encryptedMasterKey, sizeof(encryptedMasterKey), &eEncMasterKeyLen);

    // Writing into the database
    db = fopen(filename, "w");
    fprintf(db, "%s;%ld;%s;%ld;%s;%ld;%s\n", hash, eSaltLen, encodedSalt, eNonceLen, encodedNonce, eEncMasterKeyLen, encodedEncryptedMasterKey);
    fclose(db);

    // Freeing the memory allocations and clearing memory
    memset(masterKey, 0, sizeof(masterKey));
    free(encodedSalt);
    free(encodedNonce);
    free(encodedEncryptedMasterKey);
}

void unlock(){

    unsigned char *nonce;
    char *encodedNonce;
    unsigned char *encryptedMasterKey;
    char *encodedEncryptedMasterKey;
    unsigned char derivedKey[KEY_LEN];
    unsigned char *salt;
    char *encodedSalt;
    char *hash;
    char *pwd;
    char line[LINE_LEN];
    char **parsedFields;
    size_t eSaltLen, eNonceLen, eEncMasterKeyLen;
    size_t saltLen, nonceLen, encMasterKeyLen;

    // Reading the database
    db = fopen(filename, "r");
    fgets(line, LINE_LEN, db);
    fclose(db);

    // Parsing the line
    parsedFields = parse_csv(line);
    if(!parsedFields[0] || !parsedFields[1] || !parsedFields[2] || !parsedFields[3] || !parsedFields[4] || !parsedFields[5] || !parsedFields[6]){
        printf("Malformed database. Exiting...\n");
        exit(EXIT_FAILURE);
    }
    hash = parsedFields[0];
    eSaltLen = strtoul(parsedFields[1], NULL, 10);
    encodedSalt = parsedFields[2];
    eNonceLen = strtoul(parsedFields[3], NULL, 10);
    encodedNonce = parsedFields[4];
    eEncMasterKeyLen = strtoul(parsedFields[5], NULL, 10);
    encodedEncryptedMasterKey = parsedFields[6];

    // Decoding the fields
    salt = base64_decode(encodedSalt, eSaltLen, &saltLen);
    nonce = base64_decode(encodedNonce, eNonceLen, &nonceLen);
    encryptedMasterKey = base64_decode(encodedEncryptedMasterKey, eEncMasterKeyLen, &encMasterKeyLen);

    // Checking the password
    pwd = sodium_malloc(PWD_LEN);
    while(true){
        printf("Enter your master password: ");
        scanf("%s", pwd);
        if (crypto_pwhash_str_verify(hash, pwd, strlen(pwd)) != 0) {
            printf("Wrong password \n");
            continue;
        }
        break;
    }

    // Deriving symmetric key
    if (crypto_pwhash(derivedKey, sizeof(derivedKey), pwd, strlen(pwd), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        sodium_free(pwd);
        printf("Fatal error. Program ran out ouf memory. Exiting...\n");
        exit(EXIT_FAILURE);
    }

    // We don't need the password anymore. Freeing memory
    sodium_memzero(pwd, PWD_LEN);

    // Decrypting the master key
    if (crypto_secretbox_open_easy(masterKey, encryptedMasterKey, encMasterKeyLen, nonce, derivedKey) != 0) {
        sodium_free(pwd);
        printf("Forged master key. Exiting...");
        exit(EXIT_FAILURE);
    }

    // Freeing memory allocations
    free_csv_line(parsedFields);
    free(salt);
    free(nonce);
    free(encryptedMasterKey);
}

void add(){
    char url[URL_LEN];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    char *encodedNonce;
    unsigned char encryptedPwd[crypto_secretbox_MACBYTES+PWD_LEN];
    char *encodedEncryptedPwd;
    char *pwd;
    size_t eNonceLen, eEncPwdLen;

    // Reading user inputs
    printf("Enter an url: ");
    scanf("%s", url);
    pwd = sodium_malloc(PWD_LEN);
    printf("Enter a password: ");
    scanf("%s", pwd);

    // Generating a nonce
    randombytes_buf(nonce, sizeof nonce);

    // Encrypting the password
    crypto_secretbox_easy(encryptedPwd, (unsigned char*)pwd, PWD_LEN, nonce, masterKey);

    // We don't need the password anymore. Freeing memory
    sodium_memzero(pwd, PWD_LEN);

    // Encoding nonce, encryptedPassword
    encodedNonce = base64_encode(nonce, sizeof(nonce), &eNonceLen);
    encodedEncryptedPwd = base64_encode(encryptedPwd, sizeof(encryptedPwd), &eEncPwdLen);

    // Writing the database
    db = fopen(filename, "a");
    fprintf(db, "%s;%ld;%s;%ld;%s\n", url, eNonceLen, encodedNonce, eEncPwdLen, encodedEncryptedPwd);
    fclose(db);

    // Freeing memory
    free(encodedNonce);
    free(encodedEncryptedPwd);
}

void list(){
    char *encodedEncPwd;
    char *url;
    char line[LINE_LEN];
    char **parsedFields;

    // Reading the database
    db = fopen(filename, "r");
    int lc = 0;

    // Header
    printf("\nURL\tPWD\n");
    printf("-------------------------------------------------------------------------------------------------------\n");

    while(fgets(line, LINE_LEN, db) != NULL){
        if(++lc == 1) continue;

        // Parsing the line
        parsedFields = parse_csv(line);
        if(!parsedFields[0] || !parsedFields[1] || !parsedFields[2] || !parsedFields[3] || !parsedFields[4]){
            fclose(db);
            printf("Malformed database. Exiting...\n");
            exit(EXIT_FAILURE);
        }
        url = parsedFields[0];
        encodedEncPwd = parsedFields[4];

        // Showing the results
        printf("%s\t%s", url, encodedEncPwd);

        // Freeing memory
        free_csv_line(parsedFields);
    }
    fclose(db);
}

void show(){
    unsigned char *nonce;
    unsigned char *encPwd;
    unsigned char pwd[PWD_LEN];
    char *encodedNonce;
    char *encodedEncPwd;
    char *url;
    char searchedUrl[URL_LEN];
    size_t eNonceLen, eEncPwdLen;
    size_t nonceLen, encPwdLen;
    char line[LINE_LEN];
    char **parsedFields;
    bool urlFound = false;

    // Reading the url
    printf("Enter an url: ");
    scanf("%s", searchedUrl);

    // Reading the database
    db = fopen(filename, "r");
    int lc = 0;
    while(fgets(line, LINE_LEN, db) != NULL){
        if(++lc == 1) continue;

        // Parsing the line
        parsedFields = parse_csv(line);
        if(!parsedFields[0] || !parsedFields[1] || !parsedFields[2] || !parsedFields[3] || !parsedFields[4]){
            fclose(db);
            printf("Malformed database. Exiting...\n");
            exit(EXIT_FAILURE);
        }
        url = parsedFields[0];
        eNonceLen = strtoul(parsedFields[1], NULL, 10);
        encodedNonce = parsedFields[2];
        eEncPwdLen = strtoul(parsedFields[3], NULL, 10);
        encodedEncPwd = parsedFields[4];

        // Comparing url
        if(strcmp(url, searchedUrl)!=0) continue;
        urlFound = true;

        // Decoding the fields
        nonce = base64_decode(encodedNonce, eNonceLen, &nonceLen);
        encPwd = base64_decode(encodedEncPwd, eEncPwdLen, &encPwdLen);

        // Decrypting the password
        if (crypto_secretbox_open_easy(pwd, encPwd, encPwdLen, nonce, masterKey) != 0) {
            fclose(db);
            printf("Forged password. Exiting...");
            exit(EXIT_FAILURE);
        }

        // Showing the results
        printf("Password for %s is: %s\n", url, pwd);

        // Freeing memory
        free_csv_line(parsedFields);
        free(nonce);
        free(encPwd);
    }
    fclose(db);
    if(!urlFound) printf("No password found for %s\n", searchedUrl);
}

void delete(){
    char *url;
    char searchedUrl[URL_LEN];
    char line[LINE_LEN];
    char **parsedFields;
    FILE *tmp;
    char tmpFilename[strlen(filename)+4];
    bool lineRemoved = false;

    // Reading the url
    printf("Enter an url: ");
    scanf("%s", searchedUrl);

    // Reading the database
    strcpy(tmpFilename, filename);
    strcat(tmpFilename, ".tmp");
    tmp = fopen(tmpFilename, "w");
    db = fopen(filename, "r");
    int lc = 0;
    while(fgets(line, LINE_LEN, db) != NULL){

        if(++lc > 1){

            // Parsing the line
            parsedFields = parse_csv(line);
            if(!parsedFields[0] || !parsedFields[1] || !parsedFields[2] || !parsedFields[3] || !parsedFields[4]){
                fclose(db);
                fclose(tmp);
                printf("Malformed database. Exiting...\n");
                exit(EXIT_FAILURE);
            }
            url = parsedFields[0];

            // Comparing url
            if(strcmp(url, searchedUrl)==0){
                lineRemoved = true;
                printf("%s was successfully removed\n", searchedUrl);
                free_csv_line(parsedFields);
                continue;
            }
            free_csv_line(parsedFields);
        }

        // copying the line
        fprintf(tmp, "%s", line);
    }
    fclose(db);
    fclose(tmp);

    if(!lineRemoved) printf("%s not found\n", searchedUrl);

    // Deleting and removing files
    if(remove(filename) == 0){
        rename(tmpFilename, filename);
    }else{
        printf("Fatal error. An error occurs while manipulating te database file. Exiting...\n");
        exit(EXIT_FAILURE);
    }
}

void changePwd(){
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    char *encodedNonce;
    unsigned char encryptedMasterKey[crypto_secretbox_MACBYTES+sizeof(masterKey)];
    char *encodedEncryptedMasterKey;
    unsigned char derivedKey[KEY_LEN];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    char *encodedSalt;
    char *oldHash;
    char hash[crypto_pwhash_STRBYTES];
    char *pwd;
    char line[LINE_LEN];
    char **parsedFields;
    size_t eSaltLen, eNonceLen, eEncMasterKeyLen;

    // Reading the first database line
    db = fopen(filename, "r");
    fgets(line, LINE_LEN, db);
    fclose(db);

    // Parsing the line
    parsedFields = parse_csv(line);
    if(!parsedFields[0] || !parsedFields[1] || !parsedFields[2] || !parsedFields[3] || !parsedFields[4] || !parsedFields[5] || !parsedFields[6]){
        printf("Malformed database. Exiting...\n");
        exit(EXIT_FAILURE);
    }
    oldHash = parsedFields[0];

    // Checking the password
    pwd = sodium_malloc(PWD_LEN);
    while(true){
        printf("Enter your master password: ");
        scanf("%s", pwd);
        if (crypto_pwhash_str_verify(oldHash, pwd, strlen(pwd)) != 0) {
            printf("Wrong password \n");
            continue;
        }
        break;
    }

    // We don't need the password anymore. Freeing memory
    sodium_memzero(pwd, PWD_LEN);

    // Reading the new password
    printf("Enter the new master password: ");
    scanf("%s", pwd);
    // Generating new nonce and salt
    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(salt, sizeof(salt));

    // Hashing the new password
    if(crypto_pwhash_str(hash, pwd, strlen(pwd), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0){
        sodium_free(pwd);
        printf("Fatal error. Program ran out ouf memory. Exiting...\n");
        exit(EXIT_FAILURE);
    }

    // Deriving a key to encrypt the master key
    if (crypto_pwhash(derivedKey, sizeof(derivedKey), pwd, strlen(pwd), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        sodium_free(pwd);
        printf("Fatal error. Program ran out ouf memory. Exiting...\n");
        exit(EXIT_FAILURE);
    }

    // We don't need the password anymore. Freeing memory
    sodium_memzero(pwd, PWD_LEN);

    // Encrypting the master key
    crypto_secretbox_easy(encryptedMasterKey, masterKey, sizeof(masterKey), nonce, derivedKey);

    // Encoding hash, salt and nonce
    encodedSalt = base64_encode(salt, sizeof(salt), &eSaltLen);
    encodedNonce = base64_encode(nonce, sizeof(nonce), &eNonceLen);
    encodedEncryptedMasterKey = base64_encode(encryptedMasterKey, sizeof(encryptedMasterKey), &eEncMasterKeyLen);

    // Writing into the database
    db = fopen(filename, "r+");
    fprintf(db, "%s;%ld;%s;%ld;%s;%ld;%s\n", hash, eSaltLen, encodedSalt, eNonceLen, encodedNonce, eEncMasterKeyLen, encodedEncryptedMasterKey);
    fclose(db);

    // Freeing the memory allocations and clearing memory
    free_csv_line(parsedFields);
    free(encodedSalt);
    free(encodedNonce);
    free(encodedEncryptedMasterKey);
}

int main() {

    init();

    // Checking database
    db = fopen(filename, "r");
    if(db == NULL) {
        createDB();
    }
    fclose(db);

    // Final State Machine (FSM)
    while(true){

        // LOCKED State
        if(state == LOCKED){
            unlock();
            state = UNLOCKED;

        // UNLOCKED State
        }else if(state == UNLOCKED) {

            int cmd;

            help();

            // Reading a command
            while(true){
                printf("Enter a command [%d-%d]: ", EXI, LST);
                scanf("%d", &cmd);
                if(cmd < EXI || cmd > LST){
                    printf("Command unknown \n");
                    continue;
                }
                // Clearing the console
                system("clear");
                break;
            }

            // Exiting
            if (cmd == EXI) {
                memset(masterKey, 0, sizeof(masterKey));
                break;

            // Closing
            } else if (cmd == CLO) {
                memset(masterKey, 0, sizeof(masterKey));
                state = LOCKED;

            // Adding
            } else if (cmd == ADD) {
                add();

            // Deleting
            } else if (cmd == DEL) {
                delete();

            // Showing
            } else if(cmd == SHW) {
                show();

            // Changing master password
            } else if (cmd == CHP) {
                changePwd();
                state = LOCKED;

            // Listing
            } else if (cmd == LST) {
                list();
            }
        }
    }
    return 0;
}
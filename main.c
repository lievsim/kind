#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <sodium.h>
#include <string.h>
#include "state.h"
#include "cmd.h"

#define KEY_SIZE crypto_box_SEEDBYTES
#define PWD_SIZE 32

void sigHandler(int signum){
    printf("\nCaught signal %d, exiting...", signum);
    exit(EXIT_FAILURE);
}

void help(){
    printf("[0] EXI: exists the program. \n");
    printf("[1] CLO: closes the database. \n");
    printf("[2] ADD: adds a password. \n");
    printf("[3] DEL: deletes a password. \n");
    printf("[4] CHP: changes the master password. \n");
    printf("[5] LST: lists all passwords. \n");
}

int main() {

    // Scope variables
    unsigned char *key;
    char *pwd;
    char *filename;
    char hash[crypto_pwhash_STRBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    FILE *db;
    enum state s = LOCKED;

    // Initializing libsodium library
    if (sodium_init() < 0) {
        printf("Fatal error. Libsodium initialization failed. Exiting...");
        exit(EXIT_FAILURE);
    }

    // Registering a signal handler
    signal(SIGINT, sigHandler);

    // Securely allocating memory. Avoid swapping data to the disk.
    key = sodium_malloc(KEY_SIZE);
    pwd = sodium_malloc(PWD_SIZE);

    // Checking database
    filename = getenv("HOME");
    strcat(filename, "/.kind/db.txt");
    db = fopen(filename, "r");
    if(db == NULL) {

        // Scope variables
        char answer;

        // Asking for creating a new one
        printf("Database not found under %s\n", filename);
        do {
            printf("Do you want to create a new one [y|n]? ");
            scanf("%c", &answer);
        } while (answer != 'y' && answer != 'n');

        // Creating a new one
        if (answer == 'y') {
            db = fopen(filename, "w+");
            printf("Enter a master password: ");
            scanf("%s", pwd);

            // Generating the salt
            randombytes_buf(salt, sizeof(salt));

            // Hashing password
            if(crypto_pwhash_str(hash, pwd, strlen(pwd), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0){
                sodium_free(pwd);
                sodium_free(key);
                printf("Fatal error. Program ran out ouf memory. Exiting...\n");
                exit(EXIT_FAILURE);
            }
            sodium_memzero(pwd, PWD_SIZE);
            fwrite(salt, sizeof(salt), 1, db);
            fwrite(hash, sizeof(hash), 1, db);
            fclose(db);

        // Safely exiting...
        } else {
            printf("Ok this is your choice. Exiting now...\n");
            sodium_free(pwd);
            sodium_free(key);
            exit(EXIT_SUCCESS);
        }
    }

    // Final State Machine (FSM)
    while(true){

        // LOCKED State
        if(s == LOCKED){

            // Scope variables
            bool isHashCorrect;

            // Cleaning stdout
            printf("\e[1;1H\e[2J");

            // Checking the master password
            db = fopen(filename, "r");
            fread(salt, sizeof(salt), 1, db);
            fread(hash, sizeof(hash), 1, db);
            fclose(db);
            do{
                isHashCorrect = true;
                printf("Master password: ");
                scanf("%s", pwd);
                if (crypto_pwhash_str_verify(hash, pwd, strlen(pwd)) != 0) {
                    printf("Wrong password \n");
                    isHashCorrect = false;
                }
            }while(!isHashCorrect);

            // Deriving symmetric key
            if (crypto_pwhash(key, KEY_SIZE, pwd, strlen(pwd), salt, crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
                sodium_free(pwd);
                sodium_free(key);
                printf("Fatal error. Program ran out ouf memory. Exiting...\n");
                exit(EXIT_FAILURE);
            }else{
                sodium_memzero(pwd, PWD_SIZE);
                s = UNLOCKED;
            }

        // UNLOCKED State
        }else if(s == UNLOCKED) {

            // Scope variables
            unsigned short cmd;

            // Showing help
            printf("\e[1;1H\e[2J");
            help();

            // Reading a command
            do {
                printf("Enter a command [%d-%d]: ", EXI, LST);
                scanf("%hd", &cmd);
            } while (cmd < EXI || cmd > LST);

            // Exiting
            if (cmd == EXI) {
                sodium_free(pwd);
                sodium_free(key);
                printf("Exiting...\n");
                break;

            // Closing
            } else if (cmd == CLO) {
                sodium_free(pwd);
                sodium_free(key);
                s = LOCKED;

            // Adding
            } else if (cmd == ADD) {


            // Deleting
            } else if (cmd == DEL) {

            // Changing master password
            } else if (cmd == CHP) {

            // Listing
            } else if (cmd == LST) {


            }
        }
    }
    return 0;
}
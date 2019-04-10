#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <sodium.h>
#include <string.h>
#include "state.h"
#include "cmd.h"

#define KEYSIZE 256

void sigHandler(int signum){
    printf("Caught %d, exiting...", signum);
    exit(EXIT_SUCCESS);
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

    void *masterKey;
    FILE *db;

    // Initializing libsodium library
    if (sodium_init() < 0) {
        printf("Fatal Error. Exiting...");
        exit(EXIT_FAILURE);
    }

    // Registering a signal handler
    signal(SIGINT, sigHandler);

    // Opening database
    char *filename = getenv("HOME");
    strcat(filename, "/.kind/db.txt");
    db = fopen(filename, "rw");
    if(db == NULL){
        printf("Database not found under %s\n", filename);
        char answer;
        printf("Do you want to create a new one [y|n]? ");
        do{
            scanf(" %c", &answer);
        }while(answer != 'y' && answer != 'n');
        if(answer == 'y'){
            // TODO: create db
        }else{
            printf("Ok this is your choice. Exiting now...");
            exit(EXIT_SUCCESS);
        }
    }
    masterKey = sodium_malloc(KEYSIZE);

    // Final State Machine (FSM)
    enum state s = LOCKED;
    while(true){

        if(s == LOCKED){
            char *masterPwd = sodium_malloc(KEYSIZE);
            printf("Master password: ");
            scanf("%s", masterPwd);
            // TODO: PPKDF argon2 symetric key
            s = UNLOCKED;

        }else if(s == UNLOCKED) {
            printf("\e[1;1H\e[2J");
            help();
            char cmd;
            printf("Enter a command [%d-%d]: ", EXI, LST);
            do {
                scanf(" %c", &cmd);
            } while (cmd < EXI || cmd > LST);

            if (cmd == EXI) {
                // TODO: safe exit
                break;

            } else if (cmd == CLO) {

                s = LOCKED;

            } else if (cmd == ADD) {


            } else if (cmd == DEL) {


            } else if (cmd == CHP) {


            } else if (cmd == LST) {


            }
        }
    }
    return 0;
}
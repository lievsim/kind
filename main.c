#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include "state.h"
#include "cmd.h"

void sigHandler(int signum){
    printf("Caught %d, exiting...", signum);
    exit(1);
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

    // TODO: libsodium init

    // Registering a signal handler
    signal(SIGINT, sigHandler);

    // TODO: libsodium malloc
    char masterPwd[128];

    // Final State Machine (FSM)
    enum state s = LOCKED;
    while(true){

        if(s == LOCKED){

            printf("Master password: ");
            scanf("%s", masterPwd);
            // TODO: PPKDF argon2 symetric key
            s = UNLOCKED;

        }else if(s == UNLOCKED) {
            help();
            int cmd = -1;
            do {
                printf("Enter a command [%d-%d]: ", EXI, LST);
                scanf("%d", &cmd);
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
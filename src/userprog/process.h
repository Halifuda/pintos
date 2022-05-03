#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (char *file_name);
int process_wait (tid_t);
void process_exit (void);
int process_check_load(tid_t);
void process_activate (void);


/* Debug Code. */
void print_debug(void);

#endif /**< userprog/process.h */

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/synch.h"

struct lock filesys_lock; /**< lock for operating file system. */
void syscall_init (void);

#endif /**< userprog/syscall.h */

#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_exit(struct intr_frame *f, int exid)
{
    printf("%s: exit(%d)\n", thread_current()->name, exid);
    thread_exit();
}

static void syscall_write(struct intr_frame *f, int fd)
{
    char *ptr = *((char **)(f->esp) + 2);
    printf("%s", ptr);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_num = *(int *)(f->esp);
  int syscall_arg = *((int *)(f->esp) + 1);
  switch(syscall_num)
  {
    case 1:
        syscall_exit(f, syscall_arg);
        return;
    case 9:
        syscall_write(f, syscall_arg);
        return;
    default:
        break;
  }
  printf ("system call: %d %d\n",syscall_num, syscall_arg);
  thread_exit ();
}

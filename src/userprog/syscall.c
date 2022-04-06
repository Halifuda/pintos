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

static void syscall_halt(struct intr_frame *f, int arg)
{
    shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f, int exid)
{
    /* modify child_passport information. */
    struct child_passport *pp = 
      list_entry(thread_current()->chl_elem, struct child_passport, elem);
    pp->exit_id = exid;
    pp->exited = true;
    /* exit. */
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
    case SYS_HALT:
        syscall_halt(f, syscall_arg);
    case SYS_EXIT:
        syscall_exit(f, syscall_arg);
        return;
    case SYS_WRITE:
        syscall_write(f, syscall_arg);
        return;
    default:
        break;
  }
  printf ("system call: %d %d\n",syscall_num, syscall_arg);
  thread_exit ();
}

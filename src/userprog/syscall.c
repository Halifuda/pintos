#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. Code from pintosbook. */
static int get_user(const uint8_t *uaddr) {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. 
   Code from pintosbook. */
static bool put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte));
    return error_code != -1;
}

/** recording error caused by read. */
static enum read_error_number {
    READ_NO_ERROR,    /**< no error occur. */
    READ_NULL_BUFFER, /**< empty buffer. */
    READ_OVERFLOW,    /**< read overflow. */
    READ_ACTUAL_ERROR /**< error during actual read. */
} read_errno;         

/** recording error caused by read. */
static enum write_error_number 
{
    WRITE_NO_ERROR,    /**< no error occur. */
    WRITE_NULL_BUFFER, /**< empty buffer. */
    WRITE_OVERFLOW,    /**< read overflow. */
    WRITE_ACTUAL_ERROR   /**< error during actual read. */
} write_errno;

/* Read n bytes from user memory. Return count that remaining not read. 
   -1 if error occured. */
static int read_user(const uint8_t *uaddr, uint8_t *buffer, unsigned size)
{
    read_errno = READ_NO_ERROR;
    if (size == 0) return 0;                  // mustn't <= 0 because of unsigned
    if (buffer == NULL)                       // empty buffer
    {
        read_errno = READ_NULL_BUFFER;
        return -1;
    }
    if (uaddr + size > PHYS_BASE)             // overflow user space
    {
        read_errno = READ_OVERFLOW;
        return -1; 
    } 
    /* start read. */
    unsigned n = 0;
    int bytebuf = 0;
    uint8_t *ptr = uaddr;
    do{
        bytebuf = get_user(ptr);
        if (bytebuf < 0) break;
        buffer[n++] = bytebuf;
        ++ptr;
    } while (n < size); /* trust the caller to ensure the buffer is sufficient. */
    if (bytebuf < 0)                          // actual read error
    {
        read_errno = READ_ACTUAL_ERROR;
        return -1;
    }
    return (int)(size - n);
}

/* Read 4 bytes from user memory. */
static int read_user_int(const uint8_t *uaddr)
{
    int *buffer = (int *)malloc(sizeof(int));
    int n = read_user(uaddr, buffer, sizeof(int));
    int res = -1;
    if (read_errno == READ_NO_ERROR) res = *buffer;
    free(buffer);
    return res;
}

/* Write n bytes to user memory. Return cont that remaining not writen. 
   -1 if error occured. */
static int write_user(uint8_t *udst, const uint8_t *buffer, unsigned size) 
{
    write_errno = WRITE_NO_ERROR;
    if (size == 0) return 0;                    // mustn't <= 0 because of unsigned
    if (buffer == NULL)                         // empty buffer
    {
        write_errno = WRITE_NULL_BUFFER;
        return -1;
    }
    if (udst + size > PHYS_BASE)                // overflow user space
    {
        write_errno = WRITE_OVERFLOW;
        return -1;
    }
    /* caculate max possible size. */
    unsigned max_size = sizeof(buffer);
    if (max_size > size) max_size = size;
    /* start write. */
    unsigned n = 0;
    bool flag = true;
    uint8_t *ptr = udst;
    do
    {
        flag = put_user(udst, buffer[n]);
        if (flag == false) break;
        ++n;
        ++ptr;
    } while (n < max_size);
    if (flag == false)                          // actual write error
    {
        write_errno = WRITE_ACTUAL_ERROR;
        return -1;
    }
    return (int)(size - n);
}

/* Handle syscall HALT. Simply call shutdown_power_off(). */
static void syscall_halt(struct intr_frame *f)
{
    shutdown_power_off();
}

/* Handle syscall EXIT. Record exit_id into child_passport.
   Then call thread_exit(). */
static void syscall_exit(struct intr_frame *f)
{
    /* read exit status. read error will cause -1. */
    int exid = read_user_int(((uint8_t *)f->esp + 4));
    /* modify child_passport information. */
    struct child_passport *pp = 
      list_entry(thread_current()->chl_elem, struct child_passport, elem);
    pp->exit_id = exid;
    pp->exited = true;
    /* exit. */
    thread_exit();
}

/* Handle syscall WRITE. Now simply call printf(). */
static int syscall_write(struct intr_frame *f)
{
    uint8_t *arg_buffer = (uint8_t *)malloc(sizeof(uint8_t) * 12);
    read_user(((uint8_t *)f->esp + 4), arg_buffer, 12);
    if(read_errno != READ_NO_ERROR)
    {
        free(arg_buffer);
        return 0;
    }
    int fd = *(int *)arg_buffer;
    char *buffer = *(char **)(arg_buffer + 4);
    unsigned size = *(unsigned *)(arg_buffer + 8);
    putbuf(buffer, size);
    free(arg_buffer);
    return size;
}

static void
syscall_handler (struct intr_frame *f) 
{
    /* esp_dummy is not used so we use it to notes this intr is a syscall. */
    uint32_t old_esp_dummy = f->esp_dummy;
    f->esp_dummy = 0x30;
    /* read syscall number. */
    int syscall_num = read_user_int(f->esp);
    if(read_errno != READ_NO_ERROR)
    {
        printf("failed to read system call number\n");
        f->esp_dummy = old_esp_dummy;
        thread_exit();
    }
    int res = 0; /* possible return value. */
    switch (syscall_num) {
        case SYS_HALT:
            syscall_halt(f);
            return; // UN_REACHED
        case SYS_EXIT:
            syscall_exit(f);
            f->esp_dummy = old_esp_dummy;
            return;
        case SYS_WRITE:
            res = syscall_write(f);
            f->eax = res;
            f->esp_dummy = old_esp_dummy;
            return;
        default:
            break;
  }
  printf ("system call: %d\n",syscall_num);
  f->esp_dummy = old_esp_dummy;
  thread_exit ();
}

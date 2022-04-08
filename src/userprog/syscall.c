#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

/** recording error caused by read. */
static enum read_error_number {
    READ_NO_ERROR,    /**< no error occur. */
    READ_NULL_BUFFER, /**< empty buffer. */
    READ_OVERFLOW,    /**< read overflow. */
    READ_ACTUAL_ERROR /**< error during actual read. */
} read_errno;
static struct lock read_errno_lock; /**< lock for read_errno. */

/** recording error caused by read. */
static enum write_error_number {
    WRITE_NO_ERROR,    /**< no error occur. */
    WRITE_NULL_BUFFER, /**< empty buffer. */
    WRITE_OVERFLOW,    /**< read overflow. */
    WRITE_ACTUAL_ERROR /**< error during actual read. */
} write_errno;
static struct lock write_errno_lock; /**< lock for write_errno. */

static struct lock filesys_lock; /**< lock for operating file system. */

/* Acquire lock and set read error number. */
static void set_read_errno(enum read_error_number no) 
{
    lock_acquire(&read_errno_lock);
    read_errno = no;
    lock_release(&read_errno_lock);
}

/* Acquire lock and get read error number. */
static enum read_error_number get_read_errno(void) 
{
    lock_acquire(&read_errno_lock);
    enum read_error_number no = read_errno;
    lock_release(&read_errno_lock);
    return no;
}

/* Acquire lock and set write error number. */
static void set_write_errno(enum write_error_number no) 
{
    lock_acquire(&write_errno_lock);
    write_errno = no;
    lock_release(&write_errno_lock);
}

/* Acquire lock and get write error number. */
static enum write_error_number get_write_errno(void) 
{
    lock_acquire(&write_errno_lock);
    enum write_error_number no = write_errno;
    lock_release(&write_errno_lock);
    return no;
}

void
syscall_init (void) 
{
    lock_init(&read_errno_lock);
    lock_init(&write_errno_lock);
    lock_init(&filesys_lock);
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

/* Read n bytes from user memory. Return count that remaining not read. 
   -1 if error occured. 
   Will indirectly acquire read lock. */
static int read_user(const uint8_t *uaddr, uint8_t *buffer, unsigned size)
{
    set_read_errno(READ_NO_ERROR);

    if (size == 0) return 0;                  // mustn't <= 0 because of unsigned
    if (buffer == NULL)                       // empty buffer
    {
        set_read_errno(READ_NULL_BUFFER);
        return -1;
    }
    if (uaddr + size > PHYS_BASE)  // overflow user space
    {
        set_read_errno(READ_OVERFLOW);
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
    if (bytebuf < 0)    // actual read error
    {
        set_read_errno(READ_ACTUAL_ERROR);
        return -1;
    }
    return (int)(size - n);
}

/* Read 4 bytes from user memory. -1 if error occured. 
   Will indirectly acquire read lock. */
static int read_user_int(const uint8_t *uaddr)
{
    int *buffer = (int *)malloc(sizeof(int));
    int n = read_user(uaddr, buffer, sizeof(int));
    int res = -1;
    enum read_error_number no = get_read_errno();
    if (no == READ_NO_ERROR) res = *buffer;
    free(buffer);
    return res;
}

/* Get a user strlen. 
   -1 if any error occured. */
static int user_strlen(const uint8_t *uaddr)
{
    int size = 0;
    char byte = 0;
    do {
        byte = get_user(uaddr + size);
        if (byte == -1) return -1;
        ++size;
    } while (byte != '\0');
    return size;
}

/* copy user space until meet a '\0'. Return the copied size.  
   -1 if any error occured. */
static int copy_user_str(const uint8_t *uaddr, char *dst, int size) 
{
    if (dst == NULL) return 0;
    char byte = 0;
    for (int i = 0; i < size; ++i)
    {
        dst[i] = get_user(uaddr + i);
        if (dst[i] == -1) return -1;
    }
    return size;
}

/* Write n bytes to user memory. Return cont that remaining not writen. 
   -1 if error occured. 
   Will indirectly acquire write lock. */
static int write_user(uint8_t *udst, const uint8_t *buffer, unsigned size) 
{
    set_write_errno(WRITE_NO_ERROR);

    if (size == 0) return 0;                    // mustn't <= 0 because of unsigned
    if (buffer == NULL)                         // empty buffer
    {
        set_write_errno(WRITE_NULL_BUFFER);
        return -1;
    }
    if (udst + size > PHYS_BASE)  // overflow user space
    {
        set_write_errno(WRITE_OVERFLOW);
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
    if (flag == false)  // actual write error
    {
        set_write_errno(WRITE_ACTUAL_ERROR);
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
   Then call thread_exit(). 
   caller == 0 means process call this.
   caller == -1 means syscall meet a failure and call this. 
   Will indirectly acquire read lock. */
static void syscall_exit(struct intr_frame *f, int caller)
{
    /* read exit status. read error will cause -1. */
    int exid = caller;
    if (exid == 0) exid = read_user_int(((uint8_t *)f->esp + 4));
    /* if child_passport doesn't exit, means parent has exited, remove self resouce. */
    if(thread_current()->chl_elem == NULL && thread_current()->paid == -1)
    {
        /* free any resource. */
    }
    else 
    {
        /* modify child_passport information. */
        struct child_passport *pp = 
            list_entry(thread_current()->chl_elem, struct child_passport, elem);
        pp->exit_id = exid;
        pp->exited = true;
    }
    /* print exit status. */
    printf("%s: exit(%d)\n", thread_current()->name, exid);
    /* exit. */
    thread_exit();
}

/* Handle syscall WRITE. Now simply call printf(). 
   Will indirectly acquire read lock. */
static int syscall_write(struct intr_frame *f)
{
    uint8_t *arg_buffer = (uint8_t *)malloc(sizeof(uint8_t) * 12);
    read_user(((uint8_t *)f->esp + 4), arg_buffer, 12);
    enum read_error_number no = get_read_errno();
    if(no != READ_NO_ERROR)
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

/* The real interface that call process_execute(). */
static int syscall_exec_handler(char *cmd_line)
{
    lock_acquire(&filesys_lock);
    int ctid = process_execute(cmd_line);
    lock_release(&filesys_lock);
    if (!process_check_load(ctid)) return -1;
    return ctid;
}

/* Do the many prepare work for call to process_execute() in a EXEC syscall.
   NOTE: passed ptr may be bad, but process_execute() do not check bad ptr.
   This is because the bad ptr is on user memory but we hope to pass kernel
   ptr to process_execute(). Thus we need check and copy in this function. */
static int syscall_exec(struct intr_frame *f) 
{
    char *cmd_line_user = (char *)read_user_int((char **)f->esp + 1);
    enum read_error_number no = get_read_errno();
    if (no != READ_NO_ERROR) 
    {
        syscall_exit(f, -1);
        return -1;
    }
    /* copy user string on kernel here. */
    /* get strlen. */
    int len = user_strlen(cmd_line_user);
    if (len == -1) return -1;
    char *cmd_line_kernel = (char *)malloc(len * sizeof(char) + 1);
    if (cmd_line_kernel == NULL) return -1;
    int size = copy_user_str(cmd_line_user, cmd_line_kernel, len);
    if(size == -1)
    { 
        /* copy failure need to be handled with free. */
        free(cmd_line_kernel);
        return -1;
    }
    int res = syscall_exec_handler(cmd_line_kernel);
    /* after process_execute(), call free. */
    free(cmd_line_kernel);
    return res;
}

static int syscall_wait(struct intr_frame *f)
{
    int child_pid = (int)read_user_int((int *)f->esp + 1);
    enum read_error_number no = get_read_errno();
    if (no != READ_NO_ERROR) return -1;
    int res = process_wait(child_pid);
    return res;
}

/* Handler to system call.
   Will indirectly acquire read lock. */
static void
syscall_handler (struct intr_frame *f) 
{
    /* read syscall number. */
    enum read_error_number old_errno = get_read_errno();

    int syscall_num = read_user_int(f->esp);

    enum read_error_number no = get_read_errno();
    if (no != READ_NO_ERROR) 
    {
        /* When failed to read syscall arguments, process should have return in
         * -1. */
        set_read_errno(old_errno);
        syscall_exit(f, -1);
        return;
    }
    int res = 0; /* possible return value. */
    switch (syscall_num) 
    {
        case SYS_HALT:
            set_read_errno(old_errno);
            syscall_halt(f);
            return; // UN_REACHED

        case SYS_EXIT:
            syscall_exit(f, 0);
            set_read_errno(old_errno);
            return;

        case SYS_EXEC:
            res = syscall_exec(f);
            f->eax = res;
            set_read_errno(old_errno);
            return;
        
        case SYS_WAIT:
            res = syscall_wait(f);
            f->eax = res;
            set_read_errno(old_errno);
            return;

        case SYS_WRITE:
            res = syscall_write(f);
            f->eax = res;
            set_read_errno(old_errno);
            return;

        default:
            break;
  }
  printf("system call: %d\n", syscall_num);
  set_read_errno(old_errno);
  thread_exit ();
}

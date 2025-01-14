#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/suppt.h"
#include "vm/mmap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/** Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (char *file_args) 
{
  char *fn_copy;
  tid_t tid;

  /* check if arguments size exceed page size. */
  if (strlen(file_args) + 8 >= PGSIZE) return TID_ERROR;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;

  /* parsing arguments into separated strings. */
  char *token = fn_copy, *save_ptr;
  int argc = 0, slen = 0;
  for (token = strtok_r(file_args, " ", &save_ptr); token != NULL;
        token = strtok_r(NULL, " ", &save_ptr)) 
  {
      int len = strlen(token) + 1;
      ++argc;
      strlcpy(fn_copy + slen + 8, token, len);
      slen += len;
  }
  *(int *)(fn_copy + 4) = argc;
  char *file_name = fn_copy + 8;
  /* check if the user stack page could contain these arguments. */
  if (slen + argc * 4 + 16 + (4 - slen % 4) % 4 >= PGSIZE)
  {
      palloc_free_page(fn_copy);
      return TID_ERROR;
  }
  /* make a semaphore for child to remind parent that a load operation
     has completed, whether succeeded of failed. */
  struct semaphore *load_sema =
      (struct semaphore *)malloc(sizeof(struct semaphore));
  sema_init(load_sema, 0);
  *(struct semaphore **)fn_copy = load_sema;
  /* Create a new thread to execute FILE_ARGS. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  else
    sema_down(load_sema);

  free(load_sema);

  return tid;
}

/** A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_args_)
{
  char *file_args = file_args_;
  struct intr_frame if_;
  bool success;

  /* parsing args from file_args. */
  struct semaphore *load_sema = *(struct semaphore **)file_args;
  int argc = *(int *)(file_args + 4);
  file_args += 8;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_args, &if_.eip, &if_.esp);
  /* remind parent that load has finished, whether result. */
  sema_up(load_sema);
  /* If load failed, quit. */
  if (!success) thread_exit();

  /* If load succeeded, set the child_passport load flag. */
  struct child_passport *cp =
      list_entry(thread_current()->chl_elem, struct child_passport, elem);
  cp->loaded = true;

  /* Setup MMAP table. */
  thread_current()->mmap_table = mmap_init();

  /* copying arguments onto stack, where argv[0] on the very top an so on. */
  char *token = file_args;
  int slen = 0;
  for (int cnt = 0; cnt < argc; ++cnt)
  {
      int len = strlen(token) + 1;
      if_.esp = (char *)if_.esp - len;
      strlcpy((char *)if_.esp, token, len);
      token += len;
      slen += len;
  }
  /* align esp by 4. */
  slen = (4 - slen % 4) % 4;
  if_.esp = (char *)if_.esp - slen;

  /* putting NULL on stack. */
  if_.esp = (char **)if_.esp - 1;
  *(char **)if_.esp = NULL;

  /* putting argv pointers on stack in a reversed order. */
  token = (char *)if_.esp + slen + 4;
  for (int cnt = 0; cnt < argc; ++cnt)
  {
      int len = strlen(token) + 1;
      if_.esp = (char **)if_.esp - 1;
      *(char **)if_.esp = token;
      token += len;
  } 
  /* puting argv on stack. */
  if_.esp = (char **)if_.esp - 1;
  *(int *)if_.esp = (int)((char **)if_.esp + 1);
  /* puting argc on stack. */
  if_.esp = (int *)if_.esp - 1;
  *(int *)if_.esp = argc;
  /* simulate a return address. */
  if_.esp = (int *)if_.esp - 1;

  palloc_free_page(file_args - 8); 
  // need -8 because file_args should be the 0x0 of a page.

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/** Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_tid) 
{
    /* ERROR tid. */
    if (child_tid == -1) return -1;
    
    /* find the child passport. */
    struct list *chl = &thread_current()->childlist;
    struct list_elem *e;
    struct child_passport *cp = NULL;
    for (e = list_begin(chl); e != list_end(chl); e=e->next)
    {
        cp = list_entry(e, struct child_passport, elem);
        if (cp->tid != child_tid) cp = NULL;
        else
            break;
    }
    /* no child passport. */
    if (cp == NULL) return -1;

    struct thread *child = cp->child;
    /* call WAIT after child exited. */
    if(child == NULL)
    {
        int res = -1;
        if (cp->exited == true) res = cp->exit_id; 
        /* The first time call process_wait(), remove the
           child_passport. cp is allocated in thread_create(), so wo need free(). */
        list_remove(&cp->elem);
        free(cp);
        return res;
    }
    /* waiting int a infinite loop. */
    while (child->status >= 0 && child->status < 3) 
    {
        /* couldn't understand why need 2 loops,
         * but loop belows may break when the condition still remains TRUE.
         */
        while (child->status == THREAD_READY ||
               child->status == THREAD_BLOCKED) 
        {
            thread_yield();
        }
    }
    /* child haven't exited. */
    if (cp->exited == false) return -1;
    int res = cp->exit_id;
    /* The first time call process_wait(), remove the child_passport. 
       cp is allocated in thread_create(), so wo need free(). */
    list_remove(&cp->elem);
    free(cp);
    return res;
}

/* Check if child thread successfully loaded. 
   return 0 if not and 1 if successed. -1 if any other error occured. 
   This should call only when process_execute() has returned.
   At that time, the load is surely happened. */
int process_check_load(tid_t child_tid)
{
    /* ERROR tid. */
    if (child_tid == -1) return -1;
    /* find the child passport. */
    struct list *chl = &thread_current()->childlist;
    struct list_elem *e;
    struct child_passport *cp = NULL;
    for (e = list_begin(chl); e != list_end(chl); e = e->next) {
        cp = list_entry(e, struct child_passport, elem);
        if (cp->tid != child_tid)
            cp = NULL;
        else
            break;
    }
    /* no child passport. */
    if (cp == NULL) return -1;
    return cp->loaded;
}


/** Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* print exit status. */
  printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exid);

  if (cur->exec_file != NULL) file_allow_write(cur->exec_file);

  free_mmap(cur->mmap_table);

  /* Destroy the current process's supplemental page tabel. */
    struct sup_pagedir *spd = cur->sup_pagedir;
    free_sup_pd(spd);

    /* Close file after free the spd for it will write back sth. */
    fd_vec_free(&thread_current()->fdvector);
    file_close(cur->exec_file);

    /* Destroy the current process's page directory and switch back
         to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL) {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate(NULL);
        pagedir_destroy(pd);
    }
    
}

/** Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/** We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/** ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/** For use with ELF types in printf(). */
#define PE32Wx PRIx32   /**< Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /**< Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /**< Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /**< Print Elf32_Half in hexadecimal. */

/** Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/** Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/** Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /**< Ignore. */
#define PT_LOAD    1            /**< Loadable segment. */
#define PT_DYNAMIC 2            /**< Dynamic linking info. */
#define PT_INTERP  3            /**< Name of dynamic loader. */
#define PT_NOTE    4            /**< Auxiliary info. */
#define PT_SHLIB   5            /**< Reserved. */
#define PT_PHDR    6            /**< Program header table. */
#define PT_STACK   0x6474e551   /**< Stack segment. */

/** Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /**< Executable. */
#define PF_W 2          /**< Writable. */
#define PF_R 4          /**< Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/** Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  t->sup_pagedir = alloc_sup_pd(t->pagedir);
  if (t->sup_pagedir == NULL) goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  // file_close (file);
  /* Deny the executable opened file. */
  t->exec_file = file;
  if(file!=NULL) file_deny_write(file);
  return success;
}

/** load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/** Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/** Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  size_t cur_ofs = ofs;

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Belows are codes to read data from a file to memory. 
         To implement demand paging, we do not need to do this here,
         but these code will be useful in page_fault(). */

//      /* Get a page of memory. */
//      uint8_t *kpage = alloc_frame(false);
//      if (kpage == NULL)
//        return false;

//      /* Load this page. */
//      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
//        {
//          free_frame (kpage);
//          return false; 
//        }
//      memset (kpage + page_read_bytes, 0, page_zero_bytes);

//      /* Add the page to the process's address space. */
//      if (!install_page (upage, kpage, writable)) 
//        {
//          free_frame (kpage);
//          return false; 
//        }

      /* Now implementing lazy loading. */
      
      /* Create a sup-pte for this page, recording the file info. */
      struct sup_pte *spte = alloc_spte(writable);
      if (spte == NULL) return false;
      if(!spte_set_info(spte, upage, SPD_FILE, file, (void *)&cur_ofs,
                    (void *)&page_read_bytes))
          return false;
      if (!sign_up_spte(spte)) return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      cur_ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/** Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = alloc_frame(true);
  if(kpage == NULL)
  {
      struct frame *evt_fte = find_evict_frame();
      if (evt_fte != NULL) 
      {
          struct sup_pte *evtspte = (struct sup_pte *)evt_fte->spte;
          /* Protect this spte from being evict again. */
          spte_set_faulting(evtspte, true);
          if (evict_spte(evtspte, evtspte->vpage))
              kpage = reclaim_frame(true);
          spte_set_faulting(evtspte, false);
      }
  }
  if (kpage != NULL) 
    {
      struct sup_pte *spte = alloc_spte(true);
      spte_set_info(spte, ((uint8_t *)PHYS_BASE) - PGSIZE, SPD_MEM, find_frame_entry(kpage), NULL, NULL);
      if(!sign_up_spte(spte))
      {
          free_spte(spte);
          free_frame(kpage);
          return false;
      }
      success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
      {
          set_frame_spte(spte->mem_swap_info->fte, (void *)spte);
          *esp = PHYS_BASE;
      }
      else
        free_frame (kpage);
    }
  return success;
}

/** Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with alloc_frame().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
#include "vm/pagefault.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"

/* Find the spte by virtual address in sup pagedir of curent thread. */
struct sup_pte *page_fault_get_spte(void *vaddr)
{
    if (!is_user_vaddr(vaddr)) return NULL;
    struct sup_pagedir *spd = (struct sup_pagedir *)thread_current()->sup_pagedir;
    if (spd == NULL) return NULL;
    return find_spte(spd, pg_round_down(vaddr));
}

/* Check if a page fault need load data to a frame. */
bool page_fault_need_load(struct sup_pte *spte, bool not_present, bool write)
{
    if (!not_present) return false;
    if (spte == NULL) return false;
    if (write && (!spte_can_write(spte))) return false;
    if (spte_in_memory(spte)) return false;
    return true;
}

/* Load a page from file. */
static bool load_from_file(struct sup_pte *spte, uint8_t *kpage)
{
    struct in_file_info *info = (struct in_file_info *)spte->pointer;
    struct file *file = info->fp;
    size_t offset = info->offset;
    size_t read_bytes = info->read_bytes;

    file_seek(file, offset);
    if (file_read(file, kpage, read_bytes) != (int)read_bytes) return false;
    return true;
}

/* Load a page from swap. Currently do nothing. */
static bool load_from_swap(struct sup_pte *spte UNUSED, uint8_t *kpage UNUSED) { return false; }

/* Load a page from file or swap to memory. Allocate a frame by alloc_frame(). 
   Return the kernel virtual address. NULL if failed to allocate or load. */
uint8_t *page_fault_load_page(struct sup_pte *spte) 
{
    /* Get a frame. */
    struct frame *fte = alloc_frame_struct(false);
    if (fte == NULL) return NULL;
    uint8_t *kpage = fte->paddr;

    /* Load the page. */
    if (spte_in_file(spte)) 
    {
        if (!load_from_file(spte, kpage)) 
        {
            free_fte(fte);
            return NULL;
        }
    }
    if (spte_in_swap(spte)) 
    {
        if(!load_from_swap(spte, kpage))
        {
            free_fte(fte);
            return NULL;
        }
    }

    /* Change the spte to in-memory-spte. */
    spte_set_info(spte, spte->vpage, SPD_MEM, (void *)fte, NULL, NULL);
    return kpage;
}

/* Install a page to a user's space. Copied from process.c. */
bool page_fault_install_page(struct sup_pte *spte, uint8_t *kpage)
{
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page(t->pagedir, spte->vpage) == NULL &&
            pagedir_set_page(t->pagedir, spte->vpage, kpage, spte_can_write(spte)));
}
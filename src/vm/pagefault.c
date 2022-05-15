#include "pagefault.h"

#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include "swap.h"

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
    struct file_info *info = spte->file_info;
    struct file *file = info->fp;
    size_t offset = info->offset;
    size_t read_bytes = info->read_bytes;

    lock_acquire(&filesys_lock);
    file_seek(file, offset);
    if (file_read(file, kpage, read_bytes) != (int)read_bytes) 
    {
        lock_release(&filesys_lock);
        return false;
    }
    lock_release(&filesys_lock);
    return true;
}

/* Load a page from swap. */
static bool load_from_swap(struct sup_pte *spte, uint8_t *kpage) 
{
    read_swap(kpage, spte->mem_swap_info->sector_idx, SECCNT);
    free_swap_page(spte->mem_swap_info->sector_idx);
    return true;
}

/* Load a page from file or swap to memory. Allocate a frame by alloc_frame(). 
   Return the kernel virtual address. NULL if failed to allocate or load. */
uint8_t *page_fault_load_page(struct sup_pte *spte) 
{
    /* Get a frame. */
    struct frame *fte = alloc_frame_struct(true);
    if (fte == NULL) 
    {
        struct frame *evt_fte = find_evict_frame();
        if (evt_fte != NULL) 
        {
            if (evict_spte((struct sup_pte *)evt_fte->spte)) 
                fte = reclaim_frame_struct(true);
        }
    }
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
    if(!spte_set_info(spte, spte->vpage, SPD_MEM, (void *)fte, NULL, NULL)) 
    {
        free_frame(kpage);
        return NULL;
    }
    set_frame_spte(spte->mem_swap_info->fte, (void *)spte);
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


/* Handler function for page_fault to handle non-present fault.
   Given fault addr, access mode(w/r), access thread type(user/kernel). */
bool page_fault_not_present_handler(uint8_t *fault_addr, bool write, bool user UNUSED)
{
    /* Find the sup-pte. */
    struct sup_pte *spte = page_fault_get_spte(fault_addr);
    if (spte == NULL) return false;

    /* Check if need to load. */
    if (page_fault_need_load(spte, true, write)) 
    {
        /* Load the page from file to a frame. */
        uint8_t *kpage = page_fault_load_page(spte);
        if (kpage != NULL)  // succeeded
        {
            /* Install the page to user's space. */
            if (page_fault_install_page(spte, kpage))
                return true;
            else /* Failed to install the page. */
                free_frame(kpage);
        } /* Failed to load. */
    } /* No need to load. */

    /* Reach here if whatever error occured. */
    return false;
}
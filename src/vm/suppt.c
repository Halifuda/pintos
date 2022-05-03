#include "suppt.h"

#include <stdio.h>

#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "swap.h"

/* Allocate a sup-pagedir for a thread. Given the raw pagedir address. */
void *alloc_sup_pd(uint32_t *pagedir)
{
    struct sup_pagedir *spd =
        (struct sup_pagedir *)malloc(sizeof(struct sup_pagedir));
    if (spd == NULL) return NULL;
    spd->pagedir = pagedir;
    sup_pd_init(spd);
    return spd;
}

/* Initialize a supplemental page talbe for a thread. */
void sup_pd_init(struct sup_pagedir *spd) 
{ 
    hash_init(&spd->spthash, spte_hash_func, spte_less_func, (void *)spd); 
}

/* Help function to free spte in a sup page dir. */
static void free_spte_hash_func(struct hash_elem *e, void *aux UNUSED)
{
    struct sup_pte *spte = hash_entry(e, struct sup_pte, elem);
    free_spte(spte);
}

/* Free a sup page directory. */
void free_sup_pd(struct sup_pagedir *spd)
{
    if (spd == NULL) return;
    hash_clear(&spd->spthash, free_spte_hash_func);
    free(spd);
}

/* Return if the page referenced by spte is writable. */
bool spte_can_write(struct sup_pte *spte)
{
    return (spte->info & SPD_RW) == SPD_RW;
}

/* Return if the page is in memory. */
bool spte_in_memory(struct sup_pte *spte)
{
    return (spte->info & SPD_PLACE_MASK) == SPD_MEM;
}

/* Return if the page is in file. */
bool spte_in_file(struct sup_pte *spte)
{
    return (spte->info & SPD_PLACE_MASK) == SPD_FILE;
}

/* Return if the page is in swap. */
bool spte_in_swap(struct sup_pte *spte)
{
    return (spte->info & SPD_PLACE_MASK) == SPD_SWAP;
}

/* Set the spte write right to flag, one of SPD_RO, SPD_RW. */
static void spte_set_writable(struct sup_pte *spte, uint8_t flag)
{
    spte->info &= ~SPD_WRITE_MASK;
    spte->info |= flag;
}

/* Set the spte place info to flag, one of SPD_MEM, SPD_FILE, SPD_SWAP. */
static void spte_set_place(struct sup_pte *spte, uint8_t flag)
{
    spte->info &= ~SPD_PLACE_MASK;
    spte->info |= flag;
}

/* Allocate a sup-pte in kernel space. Given the read-write access right. */
struct sup_pte *alloc_spte(bool writable) 
{
    struct sup_pte *spte = (struct sup_pte *)malloc(sizeof(struct sup_pte));
    if (spte == NULL) return NULL;
    spte->info = (uint8_t)0;
    spte->mem_swap_info = NULL;
    spte->file_info = NULL;
    spte_set_writable(spte, writable ? SPD_RW : SPD_RO);
    return spte;
}

static bool spte_set_memory_info(struct sup_pte *, struct frame *);
static bool spte_set_file_info(struct sup_pte *, struct file *, size_t, size_t);
static bool spte_set_swap_info(struct sup_pte *, block_sector_t);

/* Set a sup-pte infomation, return true if success, false if failed.
   To call this function, be careful with the passed arguments described below:
    -- struct sup_pte *spte: the pointer to the sup-pte.
    -- uint8_t *vpage: the virtual page address this spte references.
    -- uint8_t placeinfo: the additional infomation of the spte data place, one of SPD_MEM, SPD_FILE, SPD_SWAP.
    -- void *dataptr: the pointer to the data.
        * If in memory, point it to the address;
        * If in file, point it to the file struct;
        * If in swap, point it to the swap index.
    -- void *aux1: help argument 1.
        * Do not need if in memory or swap;
        * Be the offset of the page in the file if in file.
    -- void *aux2: help argument 2.
        * Be the read bytes (PGSIZE - zero bytes) in the file page. */
bool spte_set_info(struct sup_pte *spte, uint8_t *vpage, uint8_t place, void *dataptr, void *aux1,
                   void *aux2)
{
    if (spte == NULL || vpage == NULL || is_kernel_vaddr(vpage)) return false;
    spte->vpage = vpage;
    spte_set_place(spte, place);
    if(place == SPD_MEM)
        return spte_set_memory_info(spte, (struct frame *)dataptr);
    if(place == SPD_FILE)
        return spte_set_file_info(spte, (struct file *)dataptr, *(size_t *)aux1,
                                  *(size_t *)aux2);
    if (place == SPD_SWAP) return spte_set_swap_info(spte, *(block_sector_t *)dataptr);
    return false;
}

/* Help funciton to set spte infomation if the page is in memory. */
static bool spte_set_memory_info(struct sup_pte *spte, struct frame *fte)
{
    if (spte == NULL || fte == NULL) return false;
    if (spte->mem_swap_info == NULL)
    {
        struct memory_swap_info *info =
            (struct memory_swap_info *)malloc(sizeof(struct memory_swap_info));
        if (info == NULL) return false;
        spte->mem_swap_info = info;
    }
    spte->mem_swap_info->fte = fte;
    spte->mem_swap_info->sector_idx = SWAP_SEC_ERROR;
    return true;
}

/* Help function to set spte infomation if it is a file spte. */
static bool spte_set_file_info(struct sup_pte *spte, struct file *file, size_t offset, size_t read_bytes)
{
    if (spte == NULL || file == NULL) return false;
    if(spte->file_info == NULL)
    {
        struct file_info *info =
            (struct file_info *)malloc(sizeof(struct file_info));
        if (info == NULL) return false;
        spte->file_info = info;
    }
    spte->file_info->fp = file;
    spte->file_info->offset = offset;
    spte->file_info->read_bytes = read_bytes;
    return true;
}

/* Help funciton to set spte infomation if it is a swap spte. */
static bool spte_set_swap_info(struct sup_pte *spte, block_sector_t idx) 
{
    if (spte == NULL || idx == SWAP_SEC_ERROR) return false;
    if (spte->mem_swap_info == NULL) 
    {
        struct memory_swap_info *info =
            (struct memory_swap_info *)malloc(sizeof(struct memory_swap_info));
        if (info == NULL) return false;
        spte->mem_swap_info = info;
    }
    spte->mem_swap_info->sector_idx = idx;
    spte->mem_swap_info->fte = NULL;
    return true;
}

/* Find the spte in a sup pagedir by virtual address. Return NULL it there is no such spte. */
struct sup_pte *find_spte(struct sup_pagedir *spd, void *vpage)
{
    struct sup_pte *spte = (struct sup_pte *)malloc(sizeof(struct sup_pte));
    if (spte == NULL) return NULL;
    spte->vpage = vpage;
    struct hash_elem *e = hash_find(&spd->spthash, &spte->elem);
    free(spte);
    if (e == NULL) return NULL;
    spte = hash_entry(e, struct sup_pte, elem);
    return spte;
}

/* Sign up the spte to the process's sup pagedir. */
bool sign_up_spte(struct sup_pte *spte)
{
    if (spte == NULL) return false;
    struct sup_pagedir *spd =
        (struct sup_pagedir *)thread_current()->sup_pagedir;
    if (spd == NULL) return false;
    spte->pagedir = spd->pagedir;
    if (hash_insert(&spd->spthash, &spte->elem) != NULL) return false;
    return true;
}

static void spte_write_back(struct sup_pte *spte, uint8_t *kpage)
{
    struct file *file = spte->file_info->fp;
    off_t ofs = spte->file_info->offset;
    size_t bytes = spte->file_info->read_bytes;

    file = file_reopen(file);
    if (file == NULL) return;
    while (bytes > 0) bytes -= file_write_at(file, kpage, bytes, ofs);
    file_close(file);
}

/* Help function to free a frame held by a spte. */
static void free_memory_spte(struct sup_pte *spte)
{
    struct memory_swap_info *info = spte->mem_swap_info;
    /* Write infomation back. */
    if(spte->file_info != NULL && pagedir_is_dirty(spte->pagedir, spte->vpage))
        spte_write_back(spte, (spte->mem_swap_info->fte)->paddr);
    /* do not free the physical page here, for pagedir_destroy() will free it. */
    remove_fte(info->fte);
}

/* Help function to free a spte in file. */
static void free_file_spte(struct sup_pte *spte UNUSED)
{
    /* Currently do nothing. */
    return;
}

/* Help function to free a spte in swap. */
static void free_swap_spte(struct sup_pte *spte) 
{
    return;
    if (spte->file_info != NULL && spte_can_write(spte))
    {
        uint8_t *kpage = palloc_get_page(0);
        if (kpage == NULL) return;
        read_swap(kpage, spte->mem_swap_info->sector_idx, SECCNT);
        spte_write_back(spte, kpage);
    }
    free_swap_page(spte->mem_swap_info->sector_idx);
    return; 
}

/* Free a spte and delete it from sup pagedir. */
void free_spte(struct sup_pte *spte) 
{
    struct sup_pagedir *spd =
        (struct sup_pagedir *)thread_current()->sup_pagedir;
    if (spte == NULL || spd == NULL) return;
    if (spte->mem_swap_info != NULL) 
    {
        if (spte_in_memory(spte)) free_memory_spte(spte);
        if (spte_in_swap(spte)) free_swap_spte(spte);
        free(spte->mem_swap_info);
    }
    if (spte->file_info != NULL) 
    {
        free_file_spte(spte);
        free(spte->file_info);
    }
    pagedir_clear_page(spd->pagedir, spte->vpage);
    free(spte);
}

/* evict a page to file. */
static bool evict_to_file(struct sup_pte *spte)
{
    if (spte->file_info == NULL) return false;
    if (!pagedir_is_dirty(thread_current()->pagedir, spte->vpage)) return true;
    spte_write_back(spte, (spte->mem_swap_info->fte)->paddr);
    spte_set_place(spte, SPD_FILE);
    return true;
}

/* evict a page to swap, allocate swap before call this. */
static bool evict_to_swap(struct sup_pte *spte, block_sector_t idx)
{
    struct frame *fte = spte->mem_swap_info->fte;
    write_swap(fte->paddr, idx, SECCNT);
    return spte_set_info(spte, spte->vpage, SPD_SWAP, (void *)&idx, NULL, NULL);
}

/* Evict a spte present in memory. */
bool evict_spte(struct sup_pte *spte) 
{ 
    ASSERT(spte_in_memory(spte));

    if(spte_can_write(spte))
    {
        /* Firstly try to allocate swap slot. */
        block_sector_t sec_idx = alloc_swap_page();
        if (sec_idx == SWAP_SEC_ERROR) 
        {
            if (spte->file_info == NULL) PANIC("run out of swap.");
            return evict_to_file(spte);
        }
        bool success = evict_to_swap(spte, sec_idx);
        pagedir_clear_page(spte->pagedir, spte->vpage);
        return success;
    }
    /* read only spte just need to change place. */
    spte_set_place(spte, SPD_FILE);
    pagedir_clear_page(spte->pagedir, spte->vpage);
    return true;
}

/* Return the hashed value of a sup page table entry. */
unsigned spte_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct sup_pte *spte = hash_entry(e, struct sup_pte, elem);
    return hash_bytes(&spte->vpage, sizeof(spte->vpage));
}

/* Return the comparison result of 2 sup page table entries. Compared by address. */
bool spte_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct sup_pte *pteA = hash_entry(a, struct sup_pte, elem);
    struct sup_pte *pteB = hash_entry(b, struct sup_pte, elem);
    return pteA->vpage < pteB->vpage;
}
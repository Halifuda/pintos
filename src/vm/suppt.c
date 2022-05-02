#include "suppt.h"
#include "threads/malloc.h"
#include "threads/thread.h"

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
void sup_pd_init(struct sup_pagedir *pd) 
{ 
    hash_init(&pd->spthash, spte_hash_func, spte_less_func, NULL); 
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
    spte_set_writable(spte, writable ? SPD_RW : SPD_RO);
    return spte;
}

static bool spte_set_file_info(struct sup_pte *, struct file *, size_t, size_t);

/* Set a sup-pte infomation, return true if success, false if failed.
   To call this function, be careful with the passed arguments described below:
    -- struct sup_pte *spte: the pointer to the sup-pte.
    -- uint8_t *vpage: the virtual page address this spte references.
    -- uint8_t placeinfo: the additional infomation of the spte data place, one of SPD_MEM, SPD_FILE, SPD_SWAP.
    -- void *dataptr: the pointer to the data.
        * If in memory, point it to the address;
        * If in file, point it to the file struct;
        * If in swap, point it to the swap place.
    -- void *aux1: help argument 1.
        * Do not need if in memory;
        * Be the offset of the page in the file if in file;
        ...
    -- void *aux2: help argument 2.
        * Be the read bytes (PGSIZE - zero bytes) in the file page; */
bool spte_set_info(struct sup_pte *spte, uint8_t *vpage, uint8_t place, void *dataptr, void *aux1,
                   void *aux2)
{
    spte->vpage = vpage;
    spte_set_place(spte, place);
    if(place == SPD_FILE)
        return spte_set_file_info(spte, (struct file *)dataptr, *(size_t *)aux1,
                                  *(size_t *)aux2);
    return false;
}

/* Help function to set spte infomation if it is a file spte. */
static bool spte_set_file_info(struct sup_pte *spte, struct file *file, size_t offset, size_t read_bytes)
{
    if (spte == NULL || file == NULL) return false;
    struct in_file_info *info =
        (struct in_file_info *)malloc(sizeof(struct in_file_info));
    if (info == NULL) return false;
    info->fp = file;
    info->offset = offset;
    info->read_bytes = read_bytes;
    spte->pointer = (void *)info;
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
    struct sup_pagedir *spd =
        (struct sup_pagedir *)thread_current()->sup_pagedir;
    if (spd == NULL) return false;
    if (hash_insert(&spd->spthash, &spte->elem) != NULL) return false;
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
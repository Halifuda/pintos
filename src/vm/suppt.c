#include "suppt.h"
#include "threads/malloc.h"

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

/* Allocate a sup-pte in kernel space. */
struct sup_pte *alloc_spte(void)
{
    struct sup_pte *spte = (struct sup_pte *)malloc(sizeof(struct sup_pte));
    if (spte == NULL) return NULL;
    return spte;
}

static bool spte_set_file_info(struct sup_pte *, struct file *, size_t, size_t);

/* Set a sup-pte infomation, return true if success, false if failed.
   To call this function, be careful with the passed arguments described below:
    -- struct sup_pte *spte: the pointer to the sup-pte.
    -- uint8_t *vaddr: the virtual address this spte references.
    -- uint8_t info: the additional infomation of the spte.
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
bool spte_set_info(struct sup_pte *spte, uint8_t *vaddr, uint8_t info, void *dataptr, void *aux1,
                   void *aux2)
{
    spte->vaddr = vaddr;
    spte->info = info;
    if(info == SPD_FILE)
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

/* Return the hashed value of a sup page table entry. */
unsigned spte_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct sup_pte *spte = hash_entry(e, struct sup_pte, elem);
    return hash_bytes(spte->vaddr, sizeof(spte->vaddr));
}

/* Return the comparison result of 2 sup page table entries. Compared by address. */
bool spte_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct sup_pte *pteA = hash_entry(a, struct sup_pte, elem);
    struct sup_pte *pteB = hash_entry(b, struct sup_pte, elem);
    return pteA->vaddr < pteB->vaddr;
}
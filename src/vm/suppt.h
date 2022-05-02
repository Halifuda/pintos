#ifndef VM_SUPPT_H
#define VM_SUPPT_H

#include <debug.h>
#include <hash.h>
#include <stdint.h>
#include "frame.h"

/* This is the header for implementing supplemental page table (suppt). 
   Each supplemental page table is recorded for a user process, 
   currently we donot manage demand paging for kernel memory.
   Each suppt contains multiple s-pte that the process using.
   Each s-pte is accessed from a pte. */

/* Supplemental Page Table Entry. */
struct sup_pte 
{
    uint8_t *vaddr;         /**< page virtual address. */
    uint8_t info;           /**< recorded infomation bit vector. */
    void *pointer;          /**< pointer to the detailed infomation. */
    struct hash_elem elem;  /**< hash table element. */
};

/* Detailed infomation for a sup-pte if the page is in memory. */
struct in_memory_info
{
    struct frame *fte;      /**< frame table entry address. */
};

/* Detailed infomation for a sup-pte if the page is in a file. */
struct in_file_info
{
    struct file *fp;        /**< file struct pointer. */
    size_t offset;        /**< file offset. */
    size_t read_bytes;    /**< bytes count for un-zero read. */
};

/* Page directory saved for a single user process. */
struct sup_pagedir
{
    uint32_t *pagedir;      /**< page directory. */
    struct hash spthash;      /**< hash table. */
};


/* Sup pagedir interface. */

void *alloc_sup_pd(uint32_t *);
void sup_pd_init(struct sup_pagedir *);


#define SPD_MEM 0
#define SPD_FILE 1
#define SPD_SWAP 2

/* Sup page table entry interface. */

struct sup_pte *alloc_spte(void);
bool spte_set_info(struct sup_pte *spte, uint8_t *vaddr, uint8_t info, void *dataptr, void *aux1, void *aux2);

/* Hash Table helper. */
unsigned spte_hash_func(const struct hash_elem *, void *);
bool spte_less_func(const struct hash_elem *, const struct hash_elem *,
                     void *);

#endif /**< vm/suppt.h */
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

/* Detailed infomation for a sup-pte if the page is in memory. */
struct memory_swap_info
{
    struct frame *fte;      /**< frame table entry address. */
};

/* Detailed infomation for a sup-pte if the page is in a file. */
struct file_info
{
    struct file *fp;        /**< file struct pointer. */
    size_t offset;        /**< file offset. */
    size_t read_bytes;    /**< bytes count for un-zero read. */
};

/* Supplemental Page Table Entry. */
struct sup_pte 
{
    uint8_t *vpage;                             /**< page virtual address. */
    uint8_t info;                               /**< recorded infomation bit vector. */
    struct memory_swap_info *mem_swap_info;     /**< memory of swap infomation. */
    struct file_info *file_info;                /**< file infomation(always record this). */
    struct hash_elem elem;                      /**< hash table element. */
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
void free_sup_pd(struct sup_pagedir *);

/* Sup page table entry infomation interface. */

/* spte type infomation, using first 2 bits in info. */
#define SPD_PLACE_MASK 3    /**< 11: place info mask. */
#define SPD_MEM 1           /**< 01: in memory. */
#define SPD_FILE 2          /**< 10: in file. */
#define SPD_SWAP 3          /**< 11: in swap. */
/* spte right infomation, using 3rd-4th bits in info. */
#define SPD_WRITE_MASK 12   /**< 1100: read write mask. */
#define SPD_RO 4            /**< 0100: read only. */
#define SPD_RW 8            /**< 1000: read write. */

bool spte_can_write(struct sup_pte *);
bool spte_in_memory(struct sup_pte *);
bool spte_in_file(struct sup_pte *);
bool spte_in_swap(struct sup_pte *);

/* Sup page table entry interface. */

struct sup_pte *alloc_spte(bool);
bool spte_set_info(struct sup_pte *spte, uint8_t *vpage, uint8_t place, void *dataptr, void *aux1, void *aux2);
struct sup_pte *find_spte(struct sup_pagedir *, void *);
bool sign_up_spte(struct sup_pte *);
void free_spte(struct sup_pte *);

/* Hash Table helper. */

unsigned spte_hash_func(const struct hash_elem *, void *);
bool spte_less_func(const struct hash_elem *, const struct hash_elem *,
                     void *);

#endif /**< vm/suppt.h */
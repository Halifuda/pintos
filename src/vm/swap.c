#include "swap.h"

#include "threads/synch.h"
#include <bitmap.h>

static struct block *swap;      /**< swap block device. */
static struct bitmap *usage;    /**< usage infomation of swap block. */
static struct lock swap_lock;   /**< swap lock. */

/* Get swap block device and create a bitmap to record usage. */
void swap_slot_init(void) 
{ 
    swap = block_get_role(BLOCK_SWAP);
    usage = bitmap_create(block_size(swap));
    lock_init(&swap_lock);
}

/* Allocate a page in swap, return start sector index. */
block_sector_t alloc_swap_page(void) 
{ 
    size_t sec_idx;
    lock_acquire(&swap_lock);
    sec_idx = bitmap_scan_and_flip(usage, 0, SECCNT, false);
    lock_release(&swap_lock);
    return sec_idx;
}

/* Read given number of sectors starts from idx to kpage. */
void read_swap(uint8_t *kpage, block_sector_t idx, size_t sec_cnt)
{
    ASSERT(bitmap_all(usage, idx, sec_cnt));

    lock_acquire(&swap_lock);
    for (block_sector_t i = 0; i < sec_cnt; ++i)
        block_read(swap, idx + i, kpage);
    lock_release(&swap_lock);
}

/* Write kpage to given number of sectors starts from idx. */
void write_swap(const uint8_t *kpage, block_sector_t idx, size_t sec_cnt)
{
    ASSERT(bitmap_all(usage, idx, sec_cnt));

    lock_acquire(&swap_lock);
    for (block_sector_t i = 0; i < sec_cnt; ++i)
        block_write(swap, idx + i, kpage);
    lock_release(&swap_lock);
}

void free_swap_page(block_sector_t idx)
{
    ASSERT(bitmap_all(usage, idx, SECCNT));

    lock_acquire(&swap_lock);
    bitmap_set_multiple(usage, idx, SECCNT, false);
    lock_release(&swap_lock);
}
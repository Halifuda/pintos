#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <debug.h>
#include <stdbool.h>
#include <stdint.h>

#include "devices/block.h"
#include "threads/vaddr.h"

/* sector count in a page. */
#define SECCNT ((PGSIZE + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE)
/* sector idx representing ERROR. */
#define SWAP_SEC_ERROR 0xffffffffu

void swap_slot_init(void);
block_sector_t alloc_swap_page(void);
void read_swap(uint8_t *kpage, block_sector_t idx, size_t sec_cnt);
void write_swap(const uint8_t *kpage, block_sector_t idx, size_t sec_cnt);
void free_swap_page(block_sector_t);
size_t swap_used_size(void);

#endif /**< vm/swap.h */
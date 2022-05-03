#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <debug.h>
#include <stdbool.h>
#include <stdint.h>

#include "devices/block.h"
#include "threads/vaddr.h"

/* sector count in a page. */
#define SECCNT ((PGSIZE + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE)

void swap_slot_init(void);
block_sector_t alloc_swap_page(void);

#endif /**< vm/swap.h */
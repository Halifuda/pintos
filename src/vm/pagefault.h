#ifndef VM_PAGEFAULT_H
#define VM_PAGEFAULT_H

#include <debug.h>
#include <stdbool.h>
#include <stdint.h>
#include "userprog/pagedir.h"
#include "vm/suppt.h"

/* This is the header for helper functions that page_fault() needs. */

bool page_fault_not_present_handler(uint8_t *fault_addr, bool write, bool user);
struct sup_pte *page_fault_get_spte(void *);
bool page_fault_need_load(struct sup_pte *spte, bool not_present, bool write);
uint8_t *page_fault_load_page(struct sup_pte *);
bool page_fault_install_page(struct sup_pte *, uint8_t *);

bool page_fault_grow_stk_handler(uint8_t *fault_addr, void *esp);
bool page_fault_haveto_grow(uint8_t *fault_addr, void *esp);

#endif /**< vm/pagefault.h */
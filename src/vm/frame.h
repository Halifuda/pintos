#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include <debug.h>

struct frame 
{
    uint8_t *paddr;
    struct list_elem elem;
};

void frame_table_init(void);
void *alloc_frame(bool);
void free_frame(uint8_t *);
void *reclaim_frame(bool);
void sign_up_frame(uint8_t *);
struct frame *find_frame_entry(uint8_t *);

#endif
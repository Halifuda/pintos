#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <debug.h>
#include <hash.h>
#include <list.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Frame Table Entry (fte) */
struct frame 
{
    uint8_t *paddr;             /**< (kernel virtual)page address for this frame. */
    struct hash_elem elem;      /**< hash table element. */
};

/* Frame Table interfaces. */

void frame_table_init(void);
void *alloc_frame(bool);
void free_frame(uint8_t *);
void *reclaim_frame(bool);
bool sign_up_frame(uint8_t *);

/* Frame Table operations. */

struct frame *find_frame_entry(uint8_t *);
void free_fte(struct frame *);

/* Hash Table helper. */

unsigned frame_hash_func(const struct hash_elem *, void *);
bool frame_less_func(const struct hash_elem *, const struct hash_elem *,
                     void *);

#endif /**< vm/frame.h */
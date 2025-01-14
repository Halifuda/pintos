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
    void *spte;                 /**< related sup page table. */
    struct hash_elem elem;      /**< hash table element. */
    struct list_elem l_elem;    /**< list element for hotness trace. */
};

/* Frame Table interfaces. */

void frame_table_init(void);
void *alloc_frame(bool);
struct frame *alloc_frame_struct(bool);
struct frame *sign_up_frame(uint8_t *);
void *get_frame_spte(struct frame *);
void set_frame_spte(struct frame *, void *);
void free_frame(uint8_t *);
void *reclaim_frame(bool);
struct frame *reclaim_frame_struct(bool);
size_t frame_used_size(void);

/* Frame Table operations. */

struct frame *find_frame_entry(uint8_t *);
void free_fte(struct frame *);
void remove_fte(struct frame *);

/* Frame Interface. */

void acquire_frame_lock(void);
void release_frame_lock(void);
struct list *get_frame_list(void);

/* Hash Table helper. */

unsigned frame_hash_func(const struct hash_elem *, void *);
bool frame_less_func(const struct hash_elem *, const struct hash_elem *,
                     void *);


#endif /**< vm/frame.h */
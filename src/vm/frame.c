#include "vm/frame.h"

#include "threads/malloc.h"
#include "threads/palloc.h"
#include <stdio.h>

static struct hash frame_hash;

/* Set up the frame table. */
void frame_table_init(void) 
{   
    hash_init(&frame_hash, frame_hash_func, frame_less_func, NULL);
}

/* Allocate a single frame for user.
   Return the kernel virtual address (physical address + 0xC00000000).
   If there is no free frame, return NULL.
   If zero is set to true, then will allocate a all-zero page. */
void *alloc_frame(bool zero) 
{
    int zero_flag = zero == true ? PAL_ZERO : 0;
    uint8_t *kpage = palloc_get_page(PAL_USER | zero_flag);

    /* If there is no free frame, reclaim a frame. */
    if (kpage == NULL) 
        return reclaim_frame(zero);

    /* sign up the frame to frame table. */
    if(sign_up_frame(kpage) == NULL)
    {
        palloc_free_page(kpage);
        return NULL;
    }

    return kpage;
}

/* Allocate a single frame for user. 
   Same behavior with alloc_frame(), but return a struct pointer. */
struct frame *alloc_frame_struct(bool zero)
{
    int zero_flag = zero == true ? PAL_ZERO : 0;
    uint8_t *kpage = palloc_get_page(PAL_USER | zero_flag);

    /* If there is no free frame, reclaim a frame. */
    if (kpage == NULL) 
        return reclaim_frame_struct(zero);
    
    /* sign up the frame to frame table. */
    struct frame *fte = sign_up_frame(kpage);

    /* If failed to sign up, return NULL. */
    if(fte == NULL) palloc_free_page(kpage);
    
    return fte;
}

/* Free a frame from the frame table. */
void free_frame(uint8_t *kpage) 
{
    struct frame *fte = find_frame_entry(kpage);
    if(fte == NULL) return;
    free_fte(fte);
}

/* Reclaim a frame by evicting a existing frame. */
void *reclaim_frame(bool zero UNUSED) 
{
    /* currently do nothing. */
    PANIC("run out of frame.");
    return NULL;
}

/* Reclaim a frame by evicting a existing frame.
   Same behavior with reclaim_frame(), but return a struct pointer. */
struct frame *reclaim_frame_struct(bool zero UNUSED)
{
    /* currently do nothing. */
    PANIC("run out pf frame. ");
    return NULL;
}

/* Sign up a frame noted by kernel virtual address to frame table. 
   If any unexpected condition happens, return false. Else true. */
struct frame *sign_up_frame(uint8_t *kpage) 
{
    /* allocate a new frame table entry in kernel space. */
    struct frame *fte = (struct frame *)malloc(sizeof(struct frame));
    if (fte == NULL) return NULL;
    fte->paddr = kpage;
    /* insert the frame into frame hash table. */
    /* check if there is no existing frame with the same address. */
    if (hash_insert(&frame_hash, &fte->elem) != NULL) 
    {
        free(fte);
        return NULL;
    }
    return fte;
}

/* Find a frame entry noted by kernel virtual address in frame table. */
struct frame *find_frame_entry(uint8_t *kpage)
{
    /* allocate a frame table entry to help the finding. */
    struct frame *fte = (struct frame *)malloc(sizeof(struct frame));
    if (fte == NULL) return NULL;
    fte->paddr = kpage;
    struct hash_elem *e = hash_find(&frame_hash, &fte->elem);
    free(fte);
    if (e == NULL) return NULL;
    fte = hash_entry(e, struct frame, elem);
    return fte;
}

/* free a fte, remove it from frame hash table and free the physical page. */
void free_fte(struct frame *fte) 
{
    if (fte == NULL) return;
    hash_delete(&frame_hash, &fte->elem);
    if (fte->paddr != NULL) palloc_free_page(fte->paddr);
    free(fte);
}

/* remove a fte from frame table, but do not free the related phy page. */
void remove_fte(struct frame *fte)
{
    if (fte == NULL) return;
    hash_delete(&frame_hash, &fte->elem);
    free(fte);
}

/* Return the hashed value of a frame table entry. */
unsigned frame_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    struct frame *fte = hash_entry(e, struct frame, elem);
    /* hash by address. */
    return hash_bytes(&fte->paddr, sizeof(fte->paddr));
}

/* Return the comparison result of 2 frame table entries. Compared by address. */
bool frame_less_func(const struct hash_elem *a, 
                     const struct hash_elem *b,
                     void *aux UNUSED)
{
    struct frame *fteA = hash_entry(a, struct frame, elem);
    struct frame *fteB = hash_entry(b, struct frame, elem);
    return fteA->paddr < fteB->paddr;
}

/* Debug Code. */

static void print_frame_func(struct hash_elem *e, void *aux UNUSED)
{
    struct frame *fte = hash_entry(e, struct frame, elem);
    printf("    frame: %p;\n", fte->paddr);
}

void print_frame_table(void) { hash_apply(&frame_hash, print_frame_func); }
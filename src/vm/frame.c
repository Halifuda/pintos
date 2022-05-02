#include "vm/frame.h"

#include "threads/malloc.h"
#include "threads/palloc.h"

static struct list frame_list;

/* Set up the frame table. */
void frame_table_init(void) { list_init(&frame_list); }

/* Allocate a single frame for user.
   Return the kernel virtual address (physical address + 0xC00000000).
   If there is no free frame, return NULL.
   If zero is set to true, then will allocate a all-zero page. */
void *alloc_frame(bool zero) {
    int zero_flag = zero == true ? PAL_ZERO : 0;
    uint8_t *kpage = palloc_get_page(PAL_USER | zero_flag);

    /* If there is no free frame, reclaim a frame. */
    if (kpage == NULL) {
        return reclaim_frame(zero);
    }
    /* sign up the frame to frame table. */
    sign_up_frame(kpage);

    return kpage;
}

/* Free a frame from the frame table. */
void free_frame(uint8_t *kpage) 
{
    struct frame *fte = find_frame_entry(kpage);
    if(fte == NULL) return;
    palloc_free_page(kpage);
    list_remove(&fte->elem);
    free(fte);
}

/* Reclaim a frame by evicting a existing frame. */
void *reclaim_frame(bool zero UNUSED) {
    /* currently do nothing. */
    return NULL;
}

/* Sign up a frame noted by kernel virtual address to frame table. */
void sign_up_frame(uint8_t *kpage) {
    struct frame *fte = (struct frame *)malloc(sizeof(struct frame));
    fte->paddr = kpage;
    list_push_back(&frame_list, &fte->paddr);
}

/* Find a frame entry noted by kernel virtual address in frame table. */
struct frame *find_frame_entry(uint8_t *kpage)
{
    struct list_elem *e = list_begin(&frame_list);
    struct frame *fte = NULL;
    while(e!=list_end(&frame_list))
    {
        fte = list_entry(e, struct frame, elem);
        if (fte->paddr == kpage) return fte;
        e = list_next(e);
    }
    return NULL;
}
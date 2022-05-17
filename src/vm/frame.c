#include "vm/frame.h"

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"

static struct hash frame_hash;  /**< Frame table(hash). */
static struct list frame_list;  /**< Frame list handling evict policy. */
static struct lock frame_lock;  /**< Frame system lock. */

/* Set up the frame table. */
void frame_table_init(void) 
{   
    hash_init(&frame_hash, frame_hash_func, frame_less_func, NULL);
    list_init(&frame_list);
    lock_init(&frame_lock);
}

/* Allocate a single frame for user.
   Return the kernel virtual address (physical address + 0xC00000000).
   If there is no free frame, return NULL.
   If zero is set to true, then will allocate a all-zero page. */
void *alloc_frame(bool zero) 
{
    int zero_flag = zero == true ? PAL_ZERO : 0;
    uint8_t *kpage = palloc_get_page(PAL_USER | zero_flag);

    /* If there is no free frame, leave to the caller. */
    if (kpage == NULL) return NULL;

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

    /* If there is no free frame, leave to the caller. */
    if (kpage == NULL) return NULL;

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

/* Sign up a frame noted by kernel virtual address to frame table. 
   If any unexpected condition happens, return false. Else true. */
struct frame *sign_up_frame(uint8_t *kpage) 
{
    /* allocate a new frame table entry in kernel space. */
    struct frame *fte = (struct frame *)malloc(sizeof(struct frame));
    if (fte == NULL) return NULL;
    fte->paddr = kpage;
    fte->spte = NULL;
    /* insert the frame into frame hash table. */
    /* check if there is no existing frame with the same address. */
    bool has_lock = lock_held_by_current_thread(&frame_lock);
    if(!has_lock) lock_acquire(&frame_lock);

    if (hash_insert(&frame_hash, &fte->elem) != NULL) 
    {
        free(fte);

        if(!has_lock) lock_release(&frame_lock);
        return NULL;
    }
    list_push_back(&frame_list, &fte->l_elem);

    if(!has_lock) lock_release(&frame_lock);
    return fte;
}

/* Functions to related a frame to a spte. */
void *get_frame_spte(struct frame *fte) { return fte->spte; }
void set_frame_spte(struct frame *fte, void *spte) { fte->spte = spte; }

/* Find a frame entry noted by kernel virtual address in frame table. */
struct frame *find_frame_entry(uint8_t *kpage)
{
    /* allocate a frame table entry to help the finding. */
    struct frame *fte = (struct frame *)malloc(sizeof(struct frame));
    if (fte == NULL) return NULL;
    fte->paddr = kpage;

    bool has_lock = lock_held_by_current_thread(&frame_lock);
    if(!has_lock) lock_acquire(&frame_lock);

    struct hash_elem *e = hash_find(&frame_hash, &fte->elem);

    if(!has_lock) lock_release(&frame_lock);

    free(fte);
    if (e == NULL) return NULL;
    fte = hash_entry(e, struct frame, elem);
    return fte;
}

/* free a fte, remove it from frame hash table and free the physical page. */
void free_fte(struct frame *fte) 
{
    if (fte == NULL) return;

    bool has_lock = lock_held_by_current_thread(&frame_lock);
    if(!has_lock) lock_acquire(&frame_lock);

    hash_delete(&frame_hash, &fte->elem);
    list_remove(&fte->l_elem);

    if(!has_lock) lock_release(&frame_lock);

    if (fte->paddr != NULL) palloc_free_page(fte->paddr);
    free(fte);
}

/* remove a fte from frame table, but do not free the related phy page. */
void remove_fte(struct frame *fte)
{
    if (fte == NULL) return;

    bool has_lock = lock_held_by_current_thread(&frame_lock);
    if(!has_lock) lock_acquire(&frame_lock);

    hash_delete(&frame_hash, &fte->elem);
    list_remove(&fte->l_elem);

    if(!has_lock) lock_release(&frame_lock);

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

/* return the frame that will be evict next time.
   Alway acquire lock and never release lock, we regarded this function be the start step to evict a frame. 
   DO call reclaim_frame() or reclaim_frame_struct() after this func to release lock. 
   */
struct frame *find_evict_frame(void)
{
    lock_acquire(&frame_lock);
    return list_entry(list_front(&frame_list), struct frame, l_elem);
    /* Never release lock for a real evict will happen soon. */
}

/* re allocate a frame by evicting a frame, write back before call this.
   Assume thread has already acquired evict_lock, so DO call this func after calling find_evict_frame().
   Realse the lock before return. */
void *reclaim_frame(bool zero)
{
    /* Never acquire lock, lock given by find_evict_frame(). */
    struct frame *evt_fte =
        list_entry(list_front(&frame_list), struct frame, l_elem);

    uint8_t *kpage = evt_fte->paddr;
    remove_fte(evt_fte);

    if(zero)
    {
        palloc_free_page(kpage);
        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    }

    evt_fte = sign_up_frame(kpage);

    lock_release(&frame_lock);
    return evt_fte->paddr;
}

/* re allocate a frame by evicting a frame, write back before call this. 
   Same behavior with reclaim_frame() but return struct. 
   Assume thread has already acquired evict_lock, so DO call this func after calling find_evict_frame().
   Realse the lock before return. */
struct frame *reclaim_frame_struct(bool zero) 
{
    /* Never acquire lock, lock given by find_evict_frame(). */
    struct frame *evt_fte =
        list_entry(list_front(&frame_list), struct frame, l_elem);

    uint8_t *kpage = evt_fte->paddr;
    remove_fte(evt_fte);

    if (zero) {
        palloc_free_page(kpage);
        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    }

    evt_fte = sign_up_frame(kpage);

    lock_release(&frame_lock);
    return evt_fte;
}

/* Return number of used(valid) frame. */
size_t frame_used_size(void) { return hash_size(&frame_hash); }

/* Interface acquiring frame lock. */
void acquire_frame_lock(void) { lock_acquire(&frame_lock); }
/* Interface releasing frame lock. */
void release_frame_lock(void) { lock_release(&frame_lock); }
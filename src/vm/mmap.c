#include "mmap.h"

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "suppt.h"

void *mmap_init(void) { 
    struct mmap_list *table =
        (struct mmap_list *)malloc(sizeof(struct mmap_list));
    if (table == NULL) return NULL;
    list_init(&table->maps);
    table->maxid = -1;
    return table;
}

static void remove_map_spte(off_t size, uint8_t *addr) {
    struct sup_pagedir *spd = (struct sup_pagedir *)thread_current()->sup_pagedir;
    struct sup_pte *spte;
    uint8_t *upage = addr;
    off_t off = 0;
    while(off < size) {
        spte = find_spte(spd, upage);
        if (spte == NULL) return;
        delete_spte(spte);
        off += PGSIZE;
        upage += PGSIZE;
    }
}

static struct mmap_entry *find_mmap_entry(struct mmap_list *mmaplist, mapid_t id) {
    struct list_elem *e = list_begin(&mmaplist->maps);
    struct mmap_entry *entry = NULL;
    while(e != list_end(&mmaplist->maps)) {
        entry = list_entry(e, struct mmap_entry, elem);
        if (entry->mapid == id) return entry;
        e = list_next(e);
    }
    return NULL;
}

static struct mmap_entry *alloc_map_entry(struct mmap_list *mmaplist) {
    ASSERT(mmaplist != NULL);
    struct mmap_entry *entry =
        (struct mmap_entry *)malloc(sizeof(struct mmap_entry));
    if (entry == NULL) return NULL;
    entry->mapid = mmaplist->maxid + 1;
    mmaplist->maxid += 1;
    return entry;
}

mapid_t mmap_handler(struct file *file, uint8_t *addr) {
    if (pg_ofs(addr) != 0) return -1;

    struct file *handle = file_reopen(file);

    size_t size = file_length(handle);
    if (size == 0) return -1;

    off_t offset = 0;
    uint8_t *upage = addr;
    while((size_t)offset < size) {
        size_t read_bytes = size - (size_t)offset;
        if (read_bytes > PGSIZE) read_bytes = PGSIZE;

        struct sup_pagedir *spd =
            (struct sup_pagedir *)thread_current()->sup_pagedir;
        if (find_spte(spd, upage) != NULL) {
            remove_map_spte(offset, addr);
            return -1;
        }

        struct sup_pte *spte = alloc_spte(true);
        if (spte == NULL) {
            remove_map_spte(offset, addr);
            return -1;
        }
        if (!spte_set_info(spte, upage, SPD_FILE, file, (void *)&offset,
                           (void *)&read_bytes)) {
            free_spte(spte);
            remove_map_spte(offset, addr);
            return -1;
        }
        if (!sign_up_spte(spte)) {
            free_spte(spte);
            remove_map_spte(offset, addr);
        }

        offset += read_bytes;
        upage += PGSIZE;
    }

    file_close(handle);

    struct mmap_entry *entry = alloc_map_entry((struct mmap_list *)thread_current()->mmap_table);
    if(entry == NULL) {
        remove_map_spte(size, addr);
        return -1;
    }

    entry->addr = addr;
    entry->mapsize = size;
    entry->file = file;

    list_push_back(&((struct mmap_list *)(thread_current()->mmap_table))->maps, &entry->elem);
    return entry->mapid;
}
void munmap_handler(mapid_t mapid) {
    struct mmap_entry *entry = find_mmap_entry(
        (struct mmap_list *)thread_current()->mmap_table, mapid);
    remove_map_spte(entry->mapsize, entry->addr);
    list_remove(&entry->elem);
}

void free_mmap(struct mmap_list *mmaplist) { 
    ASSERT(mmaplist != NULL);
    struct list_elem *e = list_begin(&mmaplist->maps);
    struct list_elem *n = NULL;
    struct mmap_entry *entry = NULL;
    while( e != list_end(&mmaplist->maps)) {
        n = list_next(e);
        entry = list_entry(e, struct mmap_entry, elem);
        munmap_handler(entry->mapid);
        free(entry);
        list_remove(e);
        e = n;
    }
    free(mmaplist);
}
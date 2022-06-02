#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <debug.h>
#include <stdbool.h>
#include <stdint.h>
#include <list.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

typedef int mapid_t;

/* Single MMAP record entry. */
struct mmap_entry {
    mapid_t mapid;          /**< mapid. */
    struct file *file;      /**< file pointer. */
    uint8_t *addr;          /**< map address. */
    size_t mapsize;         /**< mapped size. */
    struct list_elem elem;  /**< list element. */
};

/* MMAP entries list, held by thread. */
struct mmap_list {
    int maxid;              /**< max used mapid. */
    struct list maps;       /**< list. */
};

void *mmap_init(void);
mapid_t mmap_handler(struct file *, uint8_t *);
void munmap_handler(mapid_t);
void free_mmap(struct mmap_list *);

#endif /**< vm/mmap.h */
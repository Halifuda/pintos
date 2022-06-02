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

struct mmap_entry {
    mapid_t mapid;
    struct file *file;
    uint8_t *addr;
    size_t mapsize;
    struct list_elem elem;
};

struct mmap_list {
    int maxid;
    struct list maps;
};

void *mmap_init(void);
mapid_t mmap_handler(struct file *, uint8_t *);
void munmap_handler(mapid_t);
void free_mmap(struct mmap_list *);

#endif /**< vm/mmap.h */
#ifndef THREADS_THREAD_FD_H
#define THREADS_THREAD_FD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

/* file descriptor for user process. */
struct file_descriptor
{
    int fd;             /**< fd number. */
    int right;          /**< rights to operating this fd. */
    bool opened;        /**< if file is opened. */
    struct file *file;  /**< related file. */
};

/* vector for user thread to save fd. */
struct fd_vector
{
    size_t size;                    /**< present size of fdvec. */
    struct file_descriptor *fdvec;  /**< fd vector pointer. */
    size_t max_valid;                  /**< the max valid fd number. */
    size_t valid_cnt;                  /**< valid fd count. */
    int tid;                        /**< tid for thread holding this fd_vector. */
};

#define FD_V 1      /* fd right: valid fd. */
#define FD_R 2      /* fd right: read right. */
#define FD_W 4      /* fd right: write right. */
#define FD_OC 8     /* fd right: open/close right. */

#define FDV_SIZE 8 /* initial size for a fd vector. */

/* macros for operating fd right. */
#define get_fd_right(FD, RIGHT) ((FD)->right & (RIGHT))
#define add_fd_right(FD, RIGHT) ((FD)->right |= (RIGHT))
#define del_fd_right(FD, RIGHT) ((FD)->right &= (~RIGHT))
#define clear_fd_right(FD) ((FD)->right = 0)
#define set_fd_right(FD, RIGHT) ((FD)->right = (RIGHT))
#define giveall_fd_right(FD) ((FD)->right = -1)

/* macros for operating fd validation. */
#define get_fd_valid(FD) get_fd_right(FD, FD_V)
#define valid_fd(FD) add_fd_right(FD, FD_V)
#define invalid_fd(FD) del_fd_right(FD, FD_V)

void fd_init(struct file_descriptor *, int);
void fd_associate(struct file_descriptor *, struct file *);
struct file *fd_deassociate(struct file_descriptor *);
int fd_open(struct file_descriptor *, int);
int fd_close(struct file_descriptor *);

struct file_descriptor *get_fd_ptr(struct fd_vector *, int);

struct file_descriptor *fdalloc(struct fd_vector *, int);
void fdfree(struct fd_vector *, int);

void fd_vec_init(struct fd_vector *, int);
void fd_vec_closeall(struct fd_vector *);
void fd_vec_free(struct fd_vector *);

#endif
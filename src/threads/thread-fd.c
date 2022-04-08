#include "threads/thread-fd.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

/* Initialize a fd invalid. */
void fd_init(struct file_descriptor *fd, int fdid) 
{ 
    ASSERT(fd != NULL);

    fd->fd = fdid;
    fd->file = NULL;
    fd->opened = false;
    clear_fd_right(fd);
}

/* Associate a fd to a file with given right. Validate it. */
void fd_associate(struct file_descriptor *fd, struct file *file)
{
    fd->file = file;
}

/* Set fd->file to NULL, and return origin value. */
struct file *fd_deassociate(struct file_descriptor *fd)
{
    struct file *res = fd->file;
    fd->file = NULL;
    return res;
}

/* Open a fd with given right. Ensure the validation and open/close right. */
int fd_open(struct file_descriptor *fd, int right)
{
    if(fd == NULL) return -1;
    /* have no right to open or close this fd. */
    if (!get_fd_right(fd, FD_OC)) return -1;
    set_fd_right(fd, right | FD_OC | FD_V);
    fd->opened = true;
    return 1;
}

/* Close a fd. Remove read/write rights and close associated file. */
int fd_close(struct file_descriptor *fd)
{
    if (fd == NULL) return -1;
    /* have no right to open or close this fd. */
    if (!get_fd_right(fd, FD_OC)) return -1;
    del_fd_right(fd, FD_R | FD_W);
    if(fd->opened)
    {
        fd->opened = false;
        if (fd->file != NULL)
        {
            lock_acquire(&filesys_lock);
            file_close(fd->file);
            lock_release(&filesys_lock);
        }
        return 1;
    }
    return 0;
}

/* Find a fd struct pointer by fd id. */
struct file_descriptor *get_fd_ptr(struct fd_vector *vec, int fdid)
{
    struct file_descriptor *fd = NULL;
    if(fdid >= vec->size) return NULL;
    fd = &vec->fdvec[fdid];
    return fd;
}

/* Initialize a fd vector for a thread. */
void fd_vec_init(struct fd_vector *vec, int tid) 
{ 
    ASSERT(vec != NULL);
    if (vec->fdvec != NULL) free(vec->fdvec);
    vec->fdvec = (struct file_descriptor *)malloc(
        FDV_SIZE * sizeof(struct file_descriptor));
    vec->size = 8;
    vec->tid = tid;
    for (int i = 0; i < vec->size; ++i) fd_init(&vec->fdvec[i], i);
    fd_associate(&vec->fdvec[0], NULL);
    set_fd_right(&vec->fdvec[0], FD_R | FD_V);
    fd_associate(&vec->fdvec[1], NULL);
    set_fd_right(&vec->fdvec[1], FD_W | FD_V);
    vec->max_valid = 1;
    vec->valid_cnt = 2;
}

/* Close all fd (closable) in a fd vector. */
void fd_vec_closeall(struct fd_vector *vec) 
{
    if (vec->fdvec == NULL) return;
    for (int i = 2; i <= vec->max_valid;++i)
        if(get_fd_valid(&vec->fdvec[i])) fd_close(&vec->fdvec[i]);
}

/* Free a fd vector. */
void fd_vec_free(struct fd_vector *vec) 
{
    if (vec->fdvec == NULL) return;
    fd_vec_closeall(vec);
    for (int i = 0; i <= vec->max_valid; ++i) fd_deassociate(&vec->fdvec[i]);
    free(vec->fdvec);
}

/* extend allocate fd vector. */
static bool fd_vec_extend(struct fd_vector *vec)
{
    struct file_descriptor *newvec = (struct file_descriptor *)malloc(
        2 * vec->size * sizeof(struct file_descriptor));
    if (newvec == NULL) return false;
    for (int i = 0; i < vec->size; ++i)
    {
        newvec[i].fd = i;
        newvec[i].file = vec->fdvec[i].file;
        newvec[i].right = vec->fdvec[i].right;
    }
    for (int i = vec->size; i < 2 * vec->size; ++i) fd_init(&newvec[i], i);
    free(vec->fdvec);
    vec->fdvec = newvec;
    return true;
}

/* Allocate a valid fd. Give init right. */
struct file_descriptor *fdalloc(struct fd_vector *vec, int right)
{
    if (vec->size == vec->valid_cnt) 
    {
        if (!fd_vec_extend(vec)) return NULL;
    }
    int i = 0; /**< allocate place id. */
    if (vec->max_valid + 1 == vec->valid_cnt) i = ++vec->max_valid;
    else
    {
        for (i = 0; i < vec->max_valid;++i)
        {
            if (!get_fd_valid(&vec->fdvec[i])) break;
        }
    }
    set_fd_right(&vec->fdvec[i], right);
    valid_fd(&vec->fdvec[i]);
    vec->valid_cnt++;
    return &vec->fdvec[i];
}

/* Free a fd from a given fd vector. */
void fdfree(struct fd_vector *vec, int fd)
{
    if (fd > vec->max_valid) return;
    vec->valid_cnt--;
    clear_fd_right(&vec->fdvec[fd]);
    if(fd==vec->max_valid)
    {
        while (!get_fd_valid(&vec->fdvec[vec->max_valid])) vec->max_valid--;
    }
}
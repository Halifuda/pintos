#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "threads/fixed-point.h"

/** States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /**< Running thread. */
    THREAD_READY,       /**< Not running but ready to run. */
    THREAD_BLOCKED,     /**< Waiting for an event to trigger. */
    THREAD_DYING        /**< About to be destroyed. */
  };

/** Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /**< Error value for tid_t. */

/** Thread priorities. */
#define PRI_MIN 0                       /**< Lowest priority. */
#define PRI_DEFAULT 31                  /**< Default priority. */
#define PRI_MAX 63                      /**< Highest priority. */

/** A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/** The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /**< Thread identifier. */
    enum thread_status status;          /**< Thread state. */
    char name[16];                      /**< Name (for debugging purposes). */
    uint8_t *stack;                     /**< Saved stack pointer. */
    int priority;                       /**< Priority. */

    int donated_status;                 /**< Donated status, 1 for donated. */
    int donated_priority;               /**< Highest donated priority. */
    int origin_priority;                /**< Priority before donated. */
    struct list donate_list;            /**< Donate record list. */
    struct thread *waiting_thread;      /**< Waiting that thread. */
    struct lock *waiting_lock;          /**< Waiting lock. */

    int sleep_ticks;                    /**< Sleep ticks bound. */

    fp32_t recent_cpu;                  /**< Recent CPU time. (calculated) */
    int nice;                           /**< nice value. */

    struct list_elem allelem;           /**< List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /**< List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /**< Page directory. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /**< Detects stack overflow. */
  };

/** Donate record(log) for tracing the donors to a thread. */
struct donate_record 
{           
   int priority;           /**< Donated priority. */
   struct list_elem elem;  /**< List element. */
};

  /** If false (default), use round-robin scheduler.
     If true, use multi-level feedback queue scheduler.
     Controlled by kernel command-line option "-o mlfqs". */
  extern bool thread_mlfqs;

  void thread_init(void);
  void thread_start(void);

  void thread_tick(void);
  void thread_print_stats(void);

  typedef void thread_func(void *aux);
  tid_t thread_create(const char *name, int priority, thread_func *, void *);

  void thread_block(void);
  void thread_unblock(struct thread *);

  struct thread *thread_current(void);
  tid_t thread_tid(void);
  const char *thread_name(void);

  void thread_exit(void) NO_RETURN;
  void thread_yield(void);

  /** Performs some operation on thread t, given auxiliary data AUX. */
  typedef void thread_action_func(struct thread *t, void *aux);
  void thread_foreach(thread_action_func *, void *);

  int thread_get_priority(void);
  void thread_set_priority(int);

  int thread_get_nice(void);
  void thread_set_nice(int);
  int thread_get_recent_cpu(void);
  int thread_get_load_avg(void);

  /** Sleeping functions. */
  void thread_start_sleep(int64_t, int64_t);
  void thread_sleep_to_wake(struct thread *, void *);
  void thread_sleep_update(int64_t);
  bool thread_list_sleep_less_func(const struct list_elem *,
                                      const struct list_elem *, void *);
  bool thread_list_sleep_equal_func(const struct list_elem *,
                                       const struct list_elem *, void *);

  /** FIFO list operations. */
  typedef list_less_func list_equal_func;
  void list_insert_fifo_ordered(struct list *, struct list_elem *,
                                list_less_func *, list_equal_func *, void *);
  void list_adjust_fifo_ordered(struct list_elem *, list_less_func *,
                                list_equal_func *, void *);
  bool thread_list_priority_less_func(const struct list_elem *,
                                      const struct list_elem *, void *);
  bool thread_list_priority_equal_func(const struct list_elem *,
                                       const struct list_elem *, void *);

  /** Methods for priority donation. */
  struct donate_record *donate_add_record(struct thread *, struct thread *);
  void donate_update_record(struct thread *, struct donate_record *);
  void donated_thread_update(struct thread *);
  void donated_thread_return(struct thread *);
  bool thread_donate_priority_less_func(const struct list_elem *,
                                      const struct list_elem *, void *);
  bool thread_donate_priority_equal_func(const struct list_elem *,
                                       const struct list_elem *, void *);

  /** Methods for MLFQS scheduler. */
  void MLFQS_update_priority(struct thread *, void *);
  void MLFQS_update_priority_list(struct thread *, void *);
  int MLFQS_calculate_priority(struct thread *);
  void MLFQS_update_recent_cpu(struct thread *, void *);
  void MLFQS_update_running_recent_cpu(void);
  void MLFQS_update_load_avg(void);
  int MLFQS_find_max_priority(void);
  int MLFQS_update_max_priority(void);
  void MLFQS_increase_ready_threads(void);
  void MLFQS_decrease_ready_threads(void);

#endif /**< threads/thread.h */

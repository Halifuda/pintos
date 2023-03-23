#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/fixed-point.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/** Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/** List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/** List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/** List of sleeping threads. */
static struct list sleep_list;

/** Idle thread. */
static struct thread *idle_thread;

/** Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/** Lock used by allocate_tid(). */
static struct lock tid_lock;

/** Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /**< Return address. */
    thread_func *function;      /**< Function to call. */
    void *aux;                  /**< Auxiliary data for function. */
  };

/** Statistics. */
static long long idle_ticks;    /**< # of timer ticks spent idle. */
static long long kernel_ticks;  /**< # of timer ticks in kernel threads. */
static long long user_ticks;    /**< # of timer ticks in user programs. */

/** Scheduling. */
#define TIME_SLICE 4            /**< # of timer ticks to give each thread. */
static unsigned thread_ticks;   /**< # of timer ticks since last yield. */

/** If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static fp32_t load_avg; /**< # used in MLFQS scheduler. */
static int ready_threads; /**< # count for ready(running) threads in MLFQS. */
static int max_priority_place; /**< # recorder for the max-priority ready in MLFQS. */
/**< # ready lists in MLFQS, separated in priority. */
static struct list mlfqs_ready_list[64]; 

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/** Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&all_list);
  list_init (&sleep_list);

  if(thread_mlfqs)
  {
      for (int i = 0; i < 64; ++i) list_init(&mlfqs_ready_list[i]);
      ready_threads = 0; 
      /** running thread will also be counted
       * but idle() will sema_up() to add main_thread to ready_list
       * so no need for count here.
       */
      load_avg = 0;
      max_priority_place = PRI_MAX;
  }
  else list_init (&ready_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/** Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/** Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/** Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/** Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  if(thread_mlfqs)
  {
    t->nice = thread_current()->nice; /** inherite nice. */
    t->priority = MLFQS_calculate_priority(t);
  }
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t);
  if (priority > thread_get_priority()) thread_yield();

  return tid;
}

/** Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  if(thread_mlfqs && thread_current() != idle_thread)
      MLFQS_decrease_ready_threads();
  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/** Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  if(t != idle_thread)
  {
    if(thread_mlfqs)
    {
        list_push_back(&mlfqs_ready_list[t->priority], &t->elem);
        if (t->priority > max_priority_place) max_priority_place = t->priority;
        MLFQS_increase_ready_threads();
    }
    else
    {
      list_insert_fifo_ordered (&ready_list, &t->elem, 
                                thread_list_priority_less_func, 
                                thread_list_priority_equal_func, NULL);
    }
  }
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/** Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/** Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/** Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/** Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  if (thread_mlfqs) MLFQS_decrease_ready_threads();
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/** Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
  {
    if(thread_mlfqs)
    {
        list_push_back(&mlfqs_ready_list[cur->priority], &cur->elem);
        if(cur->priority > max_priority_place)
            max_priority_place = cur->priority;
    }
    else
    {
      list_insert_fifo_ordered (&ready_list, &cur->elem, 
                              thread_list_priority_less_func, 
                              thread_list_priority_equal_func, NULL);
    }
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/** Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/** Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
    if (thread_mlfqs) return;
    struct thread *cur = thread_current();

    cur->origin_priority = new_priority;
    if (cur->donated_status == 0) cur->priority = new_priority;
    else if(cur->donated_priority < new_priority)
        cur->priority = new_priority;
    
    if (!list_empty(&ready_list) &&
        thread_get_priority() <
            list_entry(list_back(&ready_list), struct thread, elem)->priority)
        thread_yield();
}

/** Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/** Sets the current thread's nice value to NICE. */
void 
thread_set_nice(int nice) 
{ 
  ASSERT(thread_mlfqs == true);
  ASSERT(nice >= -20 && nice <= 20);
  thread_current()->nice = nice;
  MLFQS_update_priority_list(thread_current(), NULL);
  if (thread_current()->priority < MLFQS_update_max_priority()) thread_yield();
}

/** Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}

/** Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return fptoi_n(load_avg * 100);
}

/** Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return fptoi_n(thread_current()->recent_cpu * 100);
}

/** Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/** Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /**< The scheduler runs with interrupts off. */
  function (aux);       /**< Execute the thread function. */
  thread_exit ();       /**< If function() returns, kill the thread. */
}

/** Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/** Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/** Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->sleep_ticks = 0;
  t->nice = 0;
  t->recent_cpu = 0;
  t->donated_status = 0;
  t->donated_priority = 0;
  t->waiting_thread = NULL;
  t->waiting_lock = NULL;
  list_init(&t->donate_list);
  if(!thread_mlfqs) t->origin_priority = priority, t->priority = priority;
  else t->priority = PRI_MAX; /** in case initial thread is created. */
  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/** Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/** Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if(thread_mlfqs)
  {
      if(max_priority_place >= 0)
      {
          struct thread *t = list_entry(
            list_pop_front(&mlfqs_ready_list[max_priority_place]),
                            struct thread, elem);
          if(list_empty(&mlfqs_ready_list[max_priority_place]))
              MLFQS_update_max_priority();
          return t;
      }
      else
          return idle_thread;
  }
  else
  {
    if (list_empty (&ready_list))
      return idle_thread;
    else
    {
        struct list_elem *t_elem = list_pop_back(&ready_list);
        return list_entry(t_elem, struct thread, elem);
    }
  }
}

/** Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/** Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
    struct thread *cur = running_thread();
    struct thread *next = next_thread_to_run();
    struct thread *prev = NULL;

    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(cur->status != THREAD_RUNNING);
    ASSERT(is_thread(next));

    if (cur != next) prev = switch_threads(cur, next);
    thread_schedule_tail(prev);
}

/** Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/** Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/** Make running thread sleep. */
void 
thread_start_sleep(int64_t sleepticks, int64_t ticks) 
{
    if (sleepticks <= 0) return;
    struct thread *t = running_thread();
    t->sleep_ticks = ticks + sleepticks;
    enum intr_level old_level = intr_disable();
    list_insert_fifo_ordered(&sleep_list, &t->elem, thread_list_sleep_less_func,
                             thread_list_sleep_equal_func, NULL);
    thread_block();
    intr_set_level(old_level);
}

/** Check a sleeping thread for if they should wake. */
void 
thread_sleep_to_wake(struct thread *t, void *aux) //aux: ticks
{
  if(t->sleep_ticks >= *(int64_t *)aux)  /** wake. */
  {
      list_remove(&t->elem);
      thread_unblock(t);
      return;
  }
}

/** Update every sleeping thread status. */
void 
thread_sleep_update(int64_t ticks)
{
    struct list_elem *e, *n;

    ASSERT(intr_get_level() == INTR_OFF);

    for (e = list_begin(&sleep_list); e != list_end(&sleep_list);
         e = n) {
        struct thread *t = list_entry(e, struct thread, elem);
        n = list_next(e);
        if (ticks < t->sleep_ticks) break;
        thread_sleep_to_wake(t, (void *)&ticks);
    }
}

/** Compare function to optimize sleep alarm. */
bool 
thread_list_sleep_less_func(const struct list_elem *a,
                                 const struct list_elem *b, void *aux UNUSED)
{
    return list_entry(a, struct thread, elem)->sleep_ticks <
           list_entry(b, struct thread, elem)->sleep_ticks;
}

/** Compare function to optimize sleep alarm. */
bool 
thread_list_sleep_equal_func(const struct list_elem *a,
                                  const struct list_elem *b, void *aux UNUSED) 
{
    return list_entry(a, struct thread, elem)->sleep_ticks ==
           list_entry(b, struct thread, elem)->sleep_ticks;
}

/** Insert an elem into a list by order. elem will be insert before
   elems which are equal to it. */
void 
list_insert_fifo_ordered(struct list *list, struct list_elem *elem,
                              list_less_func *less, list_equal_func *equal, 
                              void *aux)
{
    struct list_elem *e;

    ASSERT(list != NULL);
    ASSERT(elem != NULL);
    ASSERT(less != NULL);
    ASSERT(equal != NULL);

    for (e = list_begin(list); e != list_end(list); e = list_next(e))
        if (less(elem, e, aux) || equal(elem, e, aux)) break;
    return list_insert(e, elem);
}

/** Copy from list.c. */
static inline bool 
thread_is_tail(struct list_elem *elem) 
{
    return elem != NULL && elem->prev != NULL && elem->next == NULL;
}

/** Adjust an elem in a list by order. */
void 
list_adjust_fifo_ordered(struct list_elem *elem, list_less_func *less,
                              list_equal_func *equal, void *aux)
{
    ASSERT(elem != NULL);
    ASSERT(less != NULL);
    ASSERT(equal != NULL);

    struct list_elem *n = list_next(elem);
    while(!thread_is_tail(n))
    {
        if (less(elem, n, aux) || equal(elem, n, aux)) break;
        n = list_next(n);
    }

    if(n!=list_next(elem))
    {
        struct list_elem *ep, *en, *np;
        ep = list_prev(elem);
        en = list_next(elem);
        np = list_prev(n);
        /** remove elem */
        ep->next = en;
        en->prev = ep;
        /** insert elem betweem np, n */
        elem->prev = np;
        elem->next = n;
        np->next = elem;
        n->prev = elem;
    }
}                   

/** Compare threads in a list for their priority. */
bool 
thread_list_priority_less_func(const struct list_elem *a,
                                    const struct list_elem *b, void *aux UNUSED)
{
    return 
      list_entry(a, struct thread, elem)->priority
      < list_entry(b, struct thread, elem)->priority;
}

/** Compare threads in a list for their priority if equal. */
bool 
thread_list_priority_equal_func(const struct list_elem *a,
                                    const struct list_elem *b, void *aux UNUSED) 
{
    return list_entry(a, struct thread, elem)->priority ==
           list_entry(b, struct thread, elem)->priority;
}

/** Add a donate record to donee thread from a donor thread. */
struct donate_record *
donate_add_record(struct thread *donor, struct thread *donee)
{
    struct donate_record *rec;
    struct donor_elem *de;
    rec = (struct donate_record *)malloc(sizeof(struct donate_record));
    rec->priority = donor->priority;
    list_insert_fifo_ordered(&donee->donate_list, &rec->elem,
                             thread_donate_priority_less_func,
                             thread_donate_priority_equal_func, NULL);
    return rec;
}

/** Update an existing record by a new donor. */
void 
donate_update_record(struct thread *donor, struct donate_record *record)
{
  if (record->priority < donor->priority) record->priority = donor->priority;
  list_adjust_fifo_ordered(&record->elem, thread_donate_priority_less_func,
                           thread_donate_priority_equal_func, NULL);
}

/** Update a thread by the newest donate record. 
  If there is none, return to the origin state. */
void 
donated_thread_update(struct thread *t)
{
    if (list_empty(&t->donate_list))
    { 
        donated_thread_return(t);
        return;
    }
    struct donate_record *rec = 
    list_entry(list_back(&t->donate_list), struct donate_record, elem);
    t->donated_status = 1;
    t->donated_priority = rec->priority;
    t->priority = t->donated_priority;
    list_adjust_fifo_ordered(&t->elem, thread_list_priority_less_func,
                             thread_list_priority_equal_func, NULL);
}

/** Return current thread to the origin state before donated. */
void 
donated_thread_return(struct thread *t) 
{ 
    t->donated_status = 0;
    t->donated_priority = 0;
    t->priority = t->origin_priority;
}

/** Compare donate record in a list for their priority. */
bool 
thread_donate_priority_less_func(const struct list_elem *a,
                                      const struct list_elem *b, void *aux UNUSED)
{
  return list_entry(a, struct donate_record, elem)->priority <
         list_entry(b, struct donate_record, elem)->priority;
}

/** Compare donate_record in a list for their priority if equal. */
bool 
thread_donate_priority_equal_func(const struct list_elem *a,
                                       const struct list_elem *b, void *aux UNUSED)
{
    return list_entry(a, struct donate_record, elem)->priority ==
           list_entry(b, struct donate_record, elem)->priority;
}  

/** Calculate threads priority in MLFQS. */
int MLFQS_calculate_priority(struct thread *t)
{
    int temp = PRI_MAX - fptoi_n(t->recent_cpu / 4) - 2 * t->nice;
    if (temp < PRI_MIN) temp = PRI_MIN;
    else if (temp > PRI_MAX) temp = PRI_MAX;
    return temp;
}

/** Update threads priority in MLFQS. */
void 
MLFQS_update_priority(struct thread *t, void *aux UNUSED)
{
    t->priority = MLFQS_calculate_priority(t);
}

/** Update threads priority in MLFQS, and adjust its place in ready_lists. */
void MLFQS_update_priority_list(struct thread *t, void *aux UNUSED)
{
    int oldp = t->priority;
    MLFQS_update_priority(t, aux);
    int newp = t->priority;
    if(t->status == THREAD_READY)
    {
      if(newp != oldp)
      {
          list_remove(&t->elem);
          list_push_back(&mlfqs_ready_list[newp], &t->elem);
      }
    }
}
/** Update threads recent_cpu. */
void 
MLFQS_update_recent_cpu(struct thread *t, void *aux UNUSED)
{
    t->recent_cpu =
        fpaddi(
          fpmulfp(
            fpdivfp(2 * load_avg, fpaddi(2 * load_avg, 1)), 
            t->recent_cpu
          ),
          t->nice);
}

/** Update current thread recent_cpu. */
void 
MLFQS_update_running_recent_cpu(void) 
{
    if (thread_current() == idle_thread) return;
    thread_current()->recent_cpu = fpaddi(thread_current()->recent_cpu, 1);
}

/** Update load_avg. */
void 
MLFQS_update_load_avg(void) 
{
    static fp32_t k1 = 59 * FP32_W / 60;
    static fp32_t k2 = FP32_W / 60;
    load_avg = fpmulfp(k1, load_avg) + k2 * ready_threads;
}

/** Find the max ready priority. */
int
MLFQS_find_max_priority(void)
{
    for (int i = 63; i >= 0; --i) 
    {
        if (!list_empty(&mlfqs_ready_list[i])) return i;
    }
    return -1;
}

/** Update the max ready priority recorder. */
int MLFQS_update_max_priority(void)
{
    max_priority_place = MLFQS_find_max_priority();
    return max_priority_place;
}

/** Interface for increase ready_threads(debug). */
void 
MLFQS_increase_ready_threads(void) 
{ 
    ASSERT(thread_mlfqs == true);
    ++ready_threads;
}

/** Interface for decrease ready_threads(debug). */
void 
MLFQS_decrease_ready_threads(void) 
{
    ASSERT(thread_mlfqs == true);
    --ready_threads;
}
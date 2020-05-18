#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}


int 
allocpid(void) 
{
  pushcli();
  int pid;
  do{
    pid = nextpid;
  }
  while (!cas(&nextpid,pid,pid + 1));
  popcli();
  return pid;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  pushcli();

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(cas(&p->state,UNUSED,EMBRYO))
      goto found;

  popcli();
  return 0;

found:
  popcli();
  p->pid = allocpid();

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  for (int i = 0; i < 32; i++) {
      p->signalHandlers[i] = &p->sigactArray[i];
      p->sigactArray[i].sa_handler = SIG_DFL;
      p->sigactArray[i].sigmask = 0;  
  }
  p->pendingSignals = 0;
  p->signalMask = 0;
  //p->oldTf = (struct trapframe*)kalloc();

  return p;
}




//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  pushcli();
  
  p->state = RUNNABLE;

  popcli();
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;
  np->signalMask = curproc->signalMask;
  for (int i = 0; i < 32; i++) {
    np->sigactArray[i].sa_handler = curproc->sigactArray[i].sa_handler;
    np->sigactArray[i].sigmask = curproc->sigactArray[i].sigmask;
    np->signalHandlers[i] = &np->sigactArray[i];
  }

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  pushcli();
  cas(&(np->state), EMBRYO, RUNNABLE);
  popcli();

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  pushcli();
  if(!cas(&curproc->state,RUNNING,_ZOMBIE)){
    panic("in exit while change state to -zombie");
  }
  

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if((p->state == ZOMBIE))
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  //curproc->state = _ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  pushcli();
  for(;;){
    if(!cas(&(curproc->state),RUNNING,_SLEEPING)){
          panic("in wait while moving to -sleeping");
        }
    curproc->chan = (void *) curproc;
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;

      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        if(!cas(&p->state,ZOMBIE,UNUSED)){
          panic("in wait while moving CHILD to UNUSED");
        }
        if(!cas(&curproc->state,_SLEEPING,RUNNING)){
          panic("in wait while moving PARENT to RUNNING");
        }
        popcli();
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      curproc->chan = 0;
      cas(&curproc->state, _SLEEPING, RUNNING);
      popcli();
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    //sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  
  // Go to sleep.
  
  curproc->state = SLEEPING;
    sched();
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    pushcli();
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(!cas(&(p->state),RUNNABLE,RUNNING))
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      
      swtch(&(c->scheduler), p->context);
      switchkvm();
      cas(&(p->state),_SLEEPING,SLEEPING);
      cas(&(p->state),_RUNNABLE,RUNNABLE);
      if(cas(&(p->state),_ZOMBIE,ZOMBIE)){
        wakeup1(p->parent);
      }
      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    popcli();
  }
}



// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  //if(!holding(&ptable.lock))
    //panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  pushcli(); //DOC: yieldlock
  if(!cas(&(myproc()->state),RUNNING,_RUNNABLE)){
    panic("failed in yield");
  }
  sched();
  popcli();
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  popcli();

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  pushcli();  //DOC: sleeplock1
  release(lk);
  
  // Go to sleep.
  p->chan = chan;
  if(!(cas(&p->state,RUNNING,_SLEEPING))){
    panic("cas failed on sleep");
  }

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  popcli();
  acquire(lk);
  
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if((p->chan == chan) && (p->state == _SLEEPING || p->state == SLEEPING)){
      while (!cas(&p->state, SLEEPING, _RUNNABLE)){                         
        if (p->state == RUNNING) //it was waiting and now changing to running
          break;
      }
      if (p->state != RUNNING){
        p->chan = 0;
        cas(&p->state, _RUNNABLE, RUNNABLE);
      }
    }
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  pushcli();
  wakeup1(chan);
  popcli();
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid, int signum)
{
  if (myproc()->s_flag){
    void* sa_handler = ((struct sigaction*)myproc()->signalHandlers[signum])->sa_handler;
    if ((sa_handler != (void*)SIGCONT) && (sa_handler != (void*)SIGSTOP) && (sa_handler != (void*)SIGKILL)){
          return -1;
    }
  }

  struct proc *p;
  char flag = 0;
  if(signum < 0 || signum > 31){
    return -1;
  }
  pushcli();
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      if(!cas(&(p->pendingSignals),p->pendingSignals, (p->pendingSignals | (0x00000001 << signum)))){
        panic("in kill while turn on the bit signal");
      }
      if (signum == SIGKILL){
        p->killed = 1;
      }
      flag = 1;
      //cprintf("pid:  %d \tPending Signals = %x\n",p->pid, p->pendingSignals);
    }
  }
  popcli();
  if (!flag){
     return -1; 
  }
  return 0;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [_UNUSED]   "-unused",
  [EMBRYO]    "embryo",
  [_EMBRYO]   "-embryo",
  [SLEEPING]  "sleep ",
  [_SLEEPING] "-sleep",
  [RUNNABLE]  "runble",
  [_RUNNABLE] "-Runnable",
  [RUNNING]   "run   ",
  [_RUNNING]  "-run   ",
  [ZOMBIE]    "zombie",
  [_ZOMBIE]   "-zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

uint
sigprocmask(uint sigmask) {
    struct proc *p = myproc();
    uint oldMask = p->signalMask;
    p->signalMask = (sigmask & 0xfffdfdff);     //ignore the sigkill and sigstop bits
    //cprintf("in sigprocmask the siganlmask before change is: %d after change is:%d\n",sigmask, p->signalMask);
    return oldMask;
}

int
sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
  struct proc *p = myproc();
    if (signum < 0 || signum >= 32 || signum == 9 || signum == 17) {
        return -1;
    }
    struct sigaction* old_sigact = p->signalHandlers[signum];
    if(oldact) {
      *oldact = *old_sigact;
    }
    *((struct sigaction*)p->signalHandlers[signum]) = *act;

    return 0;
}

void
sigret(void) {
  struct proc *p = myproc();
  //----turn off the bit of the signal had treated----
  //int signum = *((int*)(p->tf->esp)); //the signum is the first argument on stack
  //p->pendingSignals = p->pendingSignals & ~(1 << signum);
  
  memmove(p->tf, p->oldTf, sizeof(struct trapframe));
  p->tf->esp += sizeof(*p->oldTf);
  p->signalMask = p->oldMask;
  p->s_flag = 0;

}

void
sigkillHandler() {
  struct proc *p = myproc();
  pushcli();
  p->killed = 1;
  // Wake process from sleep if necessary.
  while(p->state == _SLEEPING);
  cas(&(p->state),SLEEPING,_RUNNABLE);
  popcli();
}

void
sigstopHandler() { 
  struct proc *p = myproc();
  while(((p->pendingSignals & (0x1 << SIGSTOP)) != 0) && ((p->pendingSignals & (0x1 << SIGCONT)) == 0) && p->killed == 0){
    yield();
  }
  p->pendingSignals = p->pendingSignals & 0xFFF5FFFF; 
}

void
sigcontHandler(){
  struct proc *p = myproc();
  //all bits stay as are they except 17 and 19
  p->pendingSignals = p->pendingSignals & 0xFFF5FFFF;
}

void
signalsHandler() {
  struct proc *p = myproc();
  if ((p == 0) || (p->s_flag != 0) || (p->pendingSignals == 0))
    return;

  char handlerExist = 0;
  uint p_s = p->pendingSignals;
  struct sigaction* sigact = 0;
  void *signalHandler = 0;
  int i = 0;
  for(;i < 32; i++){
    if(p_s & (1 << i)){
      sigact = p->signalHandlers[i];
      if (((i == 1) && ((int)sigact->sa_handler == SIG_DFL)) || ((int)sigact->sa_handler == SIG_IGN)){
        p->pendingSignals = p->pendingSignals & ~(1 << i);
        continue;
      }
      if (((i == 17) && ((int)sigact->sa_handler == SIG_DFL)) || ((int)sigact->sa_handler == SIGSTOP)){
        sigstopHandler();
        continue;
      }
      if (((i == 19) && ((int)sigact->sa_handler == SIG_DFL)) || ((int)sigact->sa_handler == SIGCONT)){
        sigcontHandler();
        continue;
      }
      if ((i == 9) || ((int)sigact->sa_handler == SIGKILL) || ((int)sigact->sa_handler == SIG_DFL)) {
        p->pendingSignals = p->pendingSignals & ~(1 << i);
        sigkillHandler();
        continue;
      }

      if ((p->signalMask & (0x1 << i)) == 0) {
        signalHandler = sigact->sa_handler;
        handlerExist = 1;
        p->pendingSignals = p->pendingSignals & ~(1 << i);
        break;
      }
    }
  }

  if((!handlerExist)) {
    return;
  }
  int signum = i;
  p->s_flag = 1;
  p->oldMask = p->signalMask;
  // Leave room for old trap frame.
  p->tf->esp -= sizeof(struct trapframe);
  p->oldTf = (struct trapframe*) p->tf->esp;
  memmove(p->oldTf,p->tf, sizeof(struct trapframe)); //backing up trap frame

  p->signalMask = sigact->sigmask;
  p->tf->esp -= (uint)&sigret_end - (uint)&sigret_begin;
  memmove((void*)p->tf->esp, sigret_begin, (uint)&sigret_end - (uint)&sigret_begin);
  p->tf->esp -= 4;
  *((int*)p->tf->esp) = signum;                   //push the signum to esp
  p->tf->esp -= 4;
  *((int*)(p->tf->esp)) = p->tf->esp + 8;         // sigret system call code address (RET address)
  p->tf->eip = (uint)signalHandler;               // trapret will resume into signal handler
}
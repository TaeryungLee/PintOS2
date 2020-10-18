#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

struct list process_list;
struct semaphore exec_sema;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

int free_process(struct process* target_process){
  int exit_code = target_process->exit_code;
  list_remove(&target_process->elem);
  //free(target_process->process_name);
  palloc_free_page(target_process);
  return exit_code;
}

void processsys_init() {
  list_init(&process_list);
  //exec_sema = malloc(sizeof(struct semaphore));
  sema_init(&exec_sema, 0);
}

struct process* get_process_by_pid(tid_t pid){
  struct list_elem *e;
  struct process *target = NULL;
  for (e = list_begin(&process_list); e != list_tail(&process_list); e = list_next(e))
  {
    tid_t pid_curr = list_entry(e, struct process, elem)->pid;
    if (pid_curr == pid){
      target = list_entry(e, struct process, elem);
      break;
    }
  }
  return target;
}

struct process* get_current_process(void){
  tid_t pid = thread_current()->tid;
  return get_process_by_pid(pid);
}
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
    //sema_up(&exec_sema);
  } else {
    //sema_down(&exec_sema);
    struct process* new_process = palloc_get_page(PAL_ZERO);
    if(new_process == NULL){
      sema_up(&exec_sema);
      return -1;
    }
    list_push_back(&process_list, &new_process->elem);
    new_process->pid = tid;
    new_process->parent_pid = thread_current()->tid;
    sema_init(&new_process->exec_sema, 0);
    list_init(&new_process->fds);
    sema_up(&exec_sema);
    sema_down(&new_process->exec_sema);
  }
  /*sema_down(&exec_sema);
  struct process *new_process = get_process_by_pid(tid);
  while(new_process == NULL){
    new_process = get_process_by_pid(tid);
  }
  sema_down(&new_process->exec_sema);*/
  //free(exec_sema);
  //exec_sema = old_sema; //sema_init(&exec_sema, sema_old_val);

  //printf("returning tid %d\n", tid);
  
  return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
  sema_down(&exec_sema);

  char *file_name = f_name;
  struct intr_frame if_;
  bool success;
  struct process *current_process = get_current_process();
  if (current_process == NULL)
  {
    palloc_free_page(file_name);
    thread_exit();
  }
  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load(file_name, &if_.eip, &if_.esp);
  //char *save_ptr;
  //char* fname = strtok_r(file_name, " ", &save_ptr);
  //int fnamelen = strlen(fname);
  //current_process->process_name = PHYS_BASE - (fnamelen + 1);
  /*char *process_name = palloc_get_page(PAL_ZERO); //malloc(strlen(file_name) +1);
  if (process_name == NULL)
  {
    success = false;
  }
  else
  {
    strlcpy(process_name, fname, strlen(fname) + 1);
    current_process->process_name = process_name;
  }*/
  /* If load failed, quit. */
  palloc_free_page(file_name);
  if (!success)
  {
    current_process->exit_code = -1;
    sema_up(&current_process->exec_sema);
    //list_remove(&new_process->elem);
    thread_exit();
  }
  // If load was successful, set up struct process

  sema_init(&current_process->exit_sema, 0);

  current_process->lastfd = 2;

  current_process->thread = thread_current();
  char *fname = current_process->process_name;
  current_process->execfile = filesys_open(fname);
  if (current_process->execfile != NULL)
  {
    file_deny_write(current_process->execfile);
  }
  else
  {
    current_process->exit_code = -1;
    sema_up(&current_process->exec_sema);
    thread_exit();
  }

  //sema_up(&thread_current()->exec_sema);
  sema_up(&current_process->exec_sema);
  //printf("loading completed\n");


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{

  /*for (;;){
    continue;
  }*/
  //return -1;
  struct process *target_process = get_process_by_pid(child_tid);
  if(target_process == NULL){
    //printf("target process does not exist\n");
    return -1;
  } else if(target_process->parent_pid != thread_current()->tid){
    //printf("not waiting a child\n");
    return -1;
  } else if(!list_empty(&target_process->exit_sema.waiters)){
    //printf("someone is already waiting\n");
    return -1;
  } else {
    sema_down(&target_process->exit_sema);
    //list_remove(&target_process->elem);
    int exit_code = free_process(target_process);
    //printf("exit code %d\n", exit_code);
    return exit_code;
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *curr = thread_current ();
  struct process *current_process = get_current_process();
  if(current_process == NULL){
    goto pd_destroy;
  }
  uint32_t *pd;

  if (current_process->thread != NULL)
  {
    // close all fd
    if (current_process->execfile != NULL)
    {
      file_close(current_process->execfile);
    }
    //printf("pid %d \n", current_process->pid);
    while (!list_empty(&current_process->fds))
    {
      //enum intr_level old_level = intr_disable();
      //printf("begin %x, end %x\n", list_begin(&current_process->fds), list_end(&current_process->fds));
      //printf("list_empty %d\n", !list_empty(&current_process->fds));
      //printf("last fd num is %d\n", current_process->lastfd);

      struct list_elem *e = list_pop_front(&current_process->fds);
      //printf("removed %x\n", e);
      struct fd *close_fd = list_entry(e, struct fd, elem);
      file_close(close_fd->file);
      free(close_fd);
      //intr_set_level(old_level);
    }
    struct process *child = PHYS_BASE;
    while(true){
      child = NULL;
      struct list_elem *e;
      for (e = list_begin(&process_list); e != list_end(&process_list); e = list_next(e))
      {
        if (list_entry(e, struct process, elem)->parent_pid == current_process->pid)
        {
          child = list_entry(list_remove(e), struct process, elem);
          break;
        }
      }
      if (child == NULL){
        break;
      }
      if (child->exit_sema.value == 1)
      {
        free_process(child);
      }
    }
    struct list_elem *e;
    bool orphaned = true;
    if(current_process->parent_pid == 1){
      orphaned = false;
    }
    for (e = list_begin(&process_list); e != list_tail(&process_list); e = list_next(e)){
      if(list_entry(e, struct process, elem)->pid == current_process->parent_pid){
        orphaned = false;
        break;
      }
    }
    sema_up(&current_process->exit_sema);
    printf("%s: exit(%d)\n", current_process->process_name, current_process->exit_code);
    if(orphaned){
      //list_remove(&current_process->elem);
      free_process(current_process);
    }
  } 
  pd_destroy:
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  char **stack_addresses = NULL;
  char *filename_parse_temp = NULL;
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Parse the filename. */
  filename_parse_temp = palloc_get_page(PAL_ZERO);
  if (filename_parse_temp == NULL){
    goto done;
  }
  strlcpy(filename_parse_temp, file_name, PGSIZE);
  char *token;
  char *save_ptr;
  token = strtok_r(filename_parse_temp, " ", &save_ptr);
  char *fname = malloc(strlen(token) + 1);
  strlcpy(fname, token, strlen(token) + 1);
  /* Open executable file. */
  file = filesys_open (fname);
  free(fname);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  
  /* Stack will be available for arguments after setup_stack. */
  stack_addresses = (char**)palloc_get_page(PAL_ZERO);
  if (stack_addresses == NULL){
    goto done;
  }
  int argc = 0;
  int total_size = 12;
  //tokenizing command line
  while(token != NULL){
    int length = strlen(token) + 1;
    *esp = (char*)*esp - length;
    strlcpy((char *)*esp, token, length);
    stack_addresses[argc] = (char*)*esp;
    argc++;
    total_size += length + 4;
    if(total_size >= PGSIZE){
      break; // use arguments within the page size
    }
    token = strtok_r(NULL, " ", &save_ptr);
  }
  //word-align
  uint32_t alignment = (uint32_t)*esp % 4;
  *esp = (char*)*esp - alignment;
  memset(*esp, 0, alignment);
  //Push the addresses of tokens one by one to the stack

  int j = 0;
  for (j = argc; j >= 0; j--){
    *esp = (char *)*esp - sizeof(char*);
    *(char **)(*esp) = stack_addresses[j];
    //printf("stack_addresses[%d]:%x \n", j, stack_addresses[j]);
  }
  //printf("%x \n", *esp);

  // argv
  char **argv = (char**) *esp;
  *esp = (char *)*esp - sizeof(char*);
  *(char ***)(*esp) = argv;
  //printf("after argv: %x \n", *esp);

  // argc
  *esp = (char*)(*esp) - sizeof(int);
  *(int *)(*esp) = argc;
  //printf("after argc: %x \n", *esp);

  //fake return address
  *esp = (char*)(*esp) - sizeof(int);
  *(int *)(*esp) = 0;
  //printf("fake return addr pushed:%x \n", *esp);
  int execnamelen = strlen(stack_addresses[0]) + 1;
  char *execname = malloc(execnamelen);
  strlcpy(execname, stack_addresses[0], execnamelen);
  get_current_process()->process_name = execname;
  //printf("%x\n", *esp);
  //hex_dump(*esp, *esp, 64, true);
  //printf("Stack setup done\n");
  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;
  //printf("%x \n", *eip);

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(filename_parse_temp != NULL)
    palloc_free_page(filename_parse_temp);
  if(stack_addresses != NULL)
    palloc_free_page(stack_addresses);
  //get_current_process()->execfile = file;
  //file_deny_write(file);
  file_close(file);
  //printf("esp after load %x\n", *esp);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

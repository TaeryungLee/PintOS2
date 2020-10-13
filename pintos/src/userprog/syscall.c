#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"


static void syscall_handler (struct intr_frame *);

/* 
Helper Functions
*/
void read_addr(void *dest, char *src, int count);
int read_byte(char *addr);
bool write_addr(char *dest, char byte);
bool check_byte(void *addr);
void check(void *addr, int count);

/* 
Memory access handler
*/
struct lock memory;

/* 
Handler Functions
*/

void exits(int exit_code, struct intr_frame *f);
tid_t exec(char *file, struct intr_frame *f);
int wait(int tid, struct intr_frame *f);
void create(char *name, size_t size, struct intr_frame *f);
void remove(char *name, struct intr_frame *f);
void open(char *name, struct intr_frame *f);
void filesize(int fd, struct intr_frame *f);
void read(int fd, void* buffer, int size, struct intr_frame *f);
int write(int fd, void* buffer, int size, struct intr_frame *f);
void seek(int fd, int count, struct intr_frame *f);
void tell(int fd, struct intr_frame *f);
void close(int fd, struct intr_frame *f);

/*
Main Functions
*/
void syscall_init(void);
static void syscall_handler(struct intr_frame *f);

void
syscall_init (void) 
{
	lock_init(&memory);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	/*
  printf ("system call!\n");
  thread_exit ();
  */
  void *esp = f->esp;
  // Check if esp is valid
  check(esp, 4);
  // fetch syscall number
  int call_no;

  read_addr(&call_no, esp, 4);

  //debug
  //printf("syscall number: %d\n", call_no);

  switch (call_no)
  {
  	case SYS_HALT:
  	{
  		shutdown_power_off();
  		break;
  	}

  	case SYS_EXIT:
  	{
  		int exit_code;
  		read_addr(&exit_code, esp+4, 4);
  		exits(exit_code, f);
  		break;
  	}

  	case SYS_EXEC:
  	{
  		char *file;
      read_addr(&file, esp+4, 4);
      tid_t tid = exec(file, f);
      f->eax = tid;
      break;
    }

    case SYS_WAIT:
    {
    	int tid;
      read_addr(&tid, esp+4, sizeof(tid));
      f->eax = wait(tid, f);
      break;
    }


    case SYS_CREATE:
    {
    	check(esp + 4, 4);
      char *name;
      size_t size;
      read_addr(&name, esp+4, 4);
      read_addr(&size, esp+8, 4);
      create(name, size, f);
      break;
    }

    case SYS_REMOVE:
    {
      char *name;
      read_addr(&name, esp+4, 4);
      remove(name, f);
      break;
    }






    case SYS_WRITE:
    {
      int fd;
      unsigned size;
      void *buffer;
      read_addr(&fd, esp+4, 4);
      read_addr(&buffer, esp+8, 4);
      read_addr(&size, esp+12, 4);
      int ret = write(fd, buffer, size, f);
      f->eax = ret;
      break;
    }

  }
}


/* 
Helper Functions
*/
void 
read_addr(void *dest, char *src, int count)
{
	check(src, count);
	for (int i=0; i<count; i++)
		*(char *) (dest + i) = read_byte(src + i) & 0xff;
}

int 
read_byte(char *addr)
{
	int buffer;
	memcpy(&buffer, addr, 1);
	return buffer;
}

bool 
write_addr(char *dest, char byte)
{
	if (check_byte(dest))
	{
		memcpy(dest, &byte, 1);
		return true;
	}
	else
		return false;
}

bool 
check_byte(void *addr)
{
  if((addr != NULL) && (((unsigned int)addr) < ((unsigned int)PHYS_BASE)))
    return true;
  else
  	return false;
}
void 
check(void *addr, int count)
{
  for(int i=0; i < count; i++)
  {
    if(!check_byte((void *)(addr + i)))
      exits(-1,NULL);
  }
}



/* 
Handler Functions
*/

void 
exits(int exit_code, struct intr_frame *f)
{
	printf("%s: exit(%d)\n", thread_current()->name, exit_code);
	thread_current()->exit_status = exit_code;
	thread_exit();
}

tid_t
exec(char *file, struct intr_frame *f)
{
	tid_t tid = process_execute(file);
	struct thread *new = get_child(tid);
	sema_down(&new->load_sema);
	return tid;
}

int wait(int tid, struct intr_frame *f)
{
	int result = process_wait(tid);
	return result;
}

void 
create(char *name, size_t size, struct intr_frame *f)
{
  check(name, sizeof(name));
  lock_acquire(&memory);
  f->eax = filesys_create(name, size);
  lock_release(&memory);
}

void 
remove(char *name, struct intr_frame *f)
{
  check(name, sizeof(name));
  lock_acquire(&memory);
  f->eax = filesys_remove(name);
  lock_release(&memory);
}

void open(char *name, struct intr_frame *f);
void filesize(int fd, struct intr_frame *f);
void read(int fd, void* buffer, int size, struct intr_frame *f);

int
write(int fd, void* buffer, int size, struct intr_frame *f)
{
	check(buffer, size);
  lock_acquire(&memory);
  if(fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&memory);
    return size;
  }
  else if(fd == 0)
  {
    lock_release(&memory);
    return -1;
  }
}
void seek(int fd, int count, struct intr_frame *f);
void tell(int fd, struct intr_frame *f);
void close(int fd, struct intr_frame *f);









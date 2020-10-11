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

// address of return value
uint32_t *ret_val_addr;

/* 
Handler Functions
*/

void exit(int exit_code, struct intr_frame *f);
void exec(char *file, struct intr_frame *f);
void wait(int tid, struct intr_frame *f);
void create(char *name, size_t size, struct intr_frame *f);
void remove(char *name, struct intr_frame *f);
void open(char *name, struct intr_frame *f);
void filesize(int fd, struct intr_frame *f);
void read(int fd, void* buffer, int size, struct intr_frame *f);
void write(int fd, void* buffer, int size, struct intr_frame *f);
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
	check(f, sizeof(f));
  void *esp = f->esp;

  // Check if esp is valid
  check(esp, 4);

  // fetch syscall number
  int call_no;
  read_addr(&call_no, esp, 4);

  // Return value must go to eax
  *ret_val_addr = &(f->eax);

  //debug
  //printf("syscall number: %d", call_no);

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
  		exit(exit_code, f);
  		break;
  	}

  	case SYS_EXEC:
  	{
  		char *file;
      read_addr(&file, esp+4, 4);
      exec(file, f);
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
      exit(-1,NULL);
  }
}



/* 
Handler Functions
*/

void 
exit(int exit_code, struct intr_frame *f)
{
	printf("%s: exit(%d)\n", thread_current()->name, exit_code);
	thread_exit();
}

void 
exec(char *file, struct intr_frame *f)
{

}

void wait(int tid, struct intr_frame *f);

void 
create(char *name, size_t size, struct intr_frame *f)
{
  check(name, sizeof(name));
  lock_acquire(&memory);
  *ret_val_addr = filesys_create(name, size);
  lock_release(&memory);
}

void 
remove(char *name, struct intr_frame *f)
{
  check(name, sizeof(name));
  lock_acquire(&memory);
  *ret_val_addr = filesys_remove(name);
  lock_release(&memory);
}

void open(char *name, struct intr_frame *f);
void filesize(int fd, struct intr_frame *f);
void read(int fd, void* buffer, int size, struct intr_frame *f);
void write(int fd, void* buffer, int size, struct intr_frame *f);
void seek(int fd, int count, struct intr_frame *f);
void tell(int fd, struct intr_frame *f);
void close(int fd, struct intr_frame *f);









#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "vm/page.h"


static void syscall_handler (struct intr_frame *);

/* 
Helper Functions
*/
void read_addr(void *dest, char *src, int count);
int read_byte(char *addr);
bool write_addr(char *dest, char byte);
bool check_byte(void *addr);
void check(void *addr, int count);
void check_valid_string (const void *str);
void check_valid_buffer (void *buffer, unsigned size, bool to_write);
void check_vm (void *addr, unsigned size, bool to_write);

/* 
Memory access handler
*/
struct lock memory;

/* 
Handler Functions
*/

void exits(int exit_code, struct intr_frame *f);
tid_t execs(char *file, struct intr_frame *f);
int wait(int tid, struct intr_frame *f);
void create(char *name, size_t size, struct intr_frame *f);
void remove(char *name, struct intr_frame *f);
void open(char *name, struct intr_frame *f);
void filesize(int fd, struct intr_frame *f);
int read(int fd, void* buffer, int size, struct intr_frame *f);
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

  //modified 3-1.1
  check_vm(esp, 4, false);

  bool res = check_byte(esp);
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
      check(file, 4);
      // modified 3-1.1
      check_vm(file, 4, false);
      tid_t tid = execs(file, f);
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

      //debug
      //printf("create called by %s\n", name);

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

    case SYS_OPEN:
    {

      char *name;
      read_addr(&name, esp+4, 4);

      //debug
      //printf("open called by %s\n", name);

      open(name, f);
      break;
    }

    case SYS_FILESIZE:
    {
      int fd;
      read_addr(&fd, esp+4, sizeof(fd));
      filesize(fd, f);
      break;
    }

    case SYS_READ:
    {
      int fd;
      void *buffer;
      size_t size;
      read_addr(&fd, esp+4, 4);
      read_addr(&buffer, esp+8, 4);
      read_addr(&size, esp+12, 4);
      int ret = read(fd, buffer, size, f);
      f->eax = ret;
      break;
    }

    case SYS_WRITE:
    {
      //debug
      //printf("write called\n");
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

    case SYS_SEEK:
    {
      int fd;
      int count;
      read_addr(&fd, esp+4, 4);
      read_addr(&count, esp+8, 4);
      seek(fd, count, f);
      break;
    }

    case SYS_TELL:
    {
      int fd;
      read_addr(&fd, esp+4, 4);
      tell(fd, f);
      break;
    }

    case SYS_CLOSE:
    {
      int fd;
      read_addr(&fd, esp+4, 4);
      close(fd, f);
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
	/* debug 

	unsigned int a = (unsigned int) addr;
	unsigned int b = (unsigned int) PHYS_BASE;
	printf("%d, %d, %#x, %#x, %d, %d\n", a, b, a, b, (a < b), (a > (unsigned int) 0x8048000));

	*/

  if((addr != NULL) && (((unsigned int)addr) < ((unsigned int)PHYS_BASE)) && (((unsigned int)addr) > ((unsigned int) 0x8048000)))
  {
    return true;
  }
  else
  	return false;
}
void check(void *addr, int count)
{

	unsigned int *down = (unsigned int) pg_round_down(addr);
	unsigned int *up = (unsigned int) pg_round_up(addr);
	
  // debug
	//printf("%#x, %#x, %#x \n", down, addr, up);
	

	unsigned char *c = addr;
  for(int i=0; i < count; i++)
  {
    if(!check_byte((void *)(c + i)))
    {
      // debug
      //printf("fuck11");
      exits(-1, NULL);
    }
    if(((unsigned int) addr + count - 1) > up)
    	if (((unsigned int) addr == up) && ((unsigned int) addr == down))
    	{

      }
    	else
      {
        // debug
        //printf("fuck22");
    		exits(-1, NULL);
      }
      // Modified 3-1.1 we do this at check_vm
      /*
    	if((pagedir_get_page(thread_current()->pagedir, addr)) == NULL)
      {
        // debug
        printf("fuck33");
    		exits(-1, NULL);
      }
      */
  }
}

// Modified 3-1.1
// check if addr has corresponding vm_entry
void check_vm (void *addr, unsigned size, bool to_write)
{
  // requires writability?
  // this value should be true at the end of this function
  bool write_res = true;

  // does have vm?
  // this value should be true at the end of this function
  bool vm_res = true;

  for(int i=0; i < size; i++)
  {
    // get vme
    struct vm_entry *vme = find_vme(addr + i);

    // does exist
    if (vme == NULL)
    {
      //printf("no vme\n");
      vm_res = false;
    }

    if (to_write && !vme->writable)
    {
      //printf("not writable\n");
      write_res = false;
    }
  }

  if (!write_res || !vm_res)
    exits(-1, NULL);
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
execs(char *file, struct intr_frame *f)
{
	tid_t tid = process_execute(file);

	if (tid == -1)
		return tid;
	struct thread *new = get_child(tid);
	//sema_down(&new->load_sema);
  
  if (new->is_loaded != 1)
    return TID_ERROR;
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
  //debug
  //printf("create called\n");
  //printf("thread name: %s\n", thread_current()->name);
  //printf("file name %s\n", name);

  check(name, sizeof(name));
  //lock_acquire(&memory);

  f->eax = filesys_create(name, size);

  //debug
  //printf("file create %d\n", f->eax);
  //lock_release(&memory);

}

void 
remove(char *name, struct intr_frame *f)
{
  check(name, sizeof(name));
  //lock_acquire(&memory);
  f->eax = filesys_remove(name);
  //lock_release(&memory);
}

void open(char *name, struct intr_frame *f)
{
  struct file *new;
  //debug
  //printf("%#x\n", name);

  //debug

  //printf("open called\n");
  //printf("thread name: %s, %d\n", thread_current()->name, thread_current()->tid);
  //printf("file name %s\n", name);

  check(name, sizeof(name));

  // debug
  //printf("check passed\n");

  // Modified 3-1.1
  check_vm(name, sizeof(name), false);

  //debug
  //printf("checkvm passed\n");

  //lock_acquire(&memory);
  new = filesys_open(name);

  // debug
  //printf("name addr %#x, %d\n", name, new);

  if(new != NULL)
  {
    if (strcmp(thread_current()->name, name) == 0) 
    {
      file_deny_write(new);
    }
    int new_fd = process_add_file(new);
    f->eax = new_fd;
  }
  else
  {
    f->eax = -1;
  }
  //lock_release(&memory);
}

void filesize(int fd, struct intr_frame *f)
{
  int size;
  struct file *cur = process_get_file(fd);
  if(cur != NULL)
  {
    size = file_length(cur);
    f->eax = size;
  }
  else
  {
    f->eax = -1;
  }
}

int read(int fd, void* buffer, int size, struct intr_frame *f)
{
  //debug
  //printf("%#x\n", buffer);

  check(buffer, sizeof(buffer));

  // debug
  //printf("check passed\n");

  // Modified 3-1.1
  check_vm(buffer, sizeof(buffer), true);

  //debug
  //printf("checkvm passed\n");

  lock_acquire(&memory);
  printf("mem lock acquired\n");
  // printf("%d", fd);

  if(fd == 0)
  {
    for (int i = 0; i < size; i++)
    {
      write_addr((char *) (buffer + i), input_getc());
    }
    lock_release(&memory);
    printf("mem lock released\n");
    return size;
  }
  else if(fd == 1)
  {
    lock_release(&memory);
    printf("mem lock released\n");
    return -1;
  }
  else
  {
    if ((unsigned int) fd > 131)
      exits(-1, NULL);
    struct file *cur = process_get_file(fd);
    int length = 0;

    if(cur == NULL)
    {
      exits(-1, NULL);
    }
    // printf("fd!=0");

    length = file_read(cur, buffer, size);
    lock_release(&memory);
    return length;
  }
}

int
write(int fd, void* buffer, int size, struct intr_frame *f)
{
	check(buffer, sizeof(buffer));
  // Modified 3-1.1
  check_vm(buffer, sizeof(buffer), false);

  //debug

  //printf("write called\n");
  //printf("thread name: %s, %d\n", thread_current()->name, thread_current()->tid);
  //printf("fd %d\n", fd);

  if ((unsigned int) fd > 131)
    exits(-1, NULL);
  lock_acquire(&memory);
  printf("mem lock acquired\n");
  if(fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&memory);
    printf("mem lock released\n");
    return size;
  }
  else if(fd == 0)
  {
    lock_release(&memory);
    printf("mem lock released\n");
    return -1;
  }
  else
  {
    struct file *cur_file = process_get_file(fd);
    int length = 0;

    if(cur_file == NULL)
    {
      lock_release(&memory);
      printf("mem lock released\n");
      return -1;
    }

    else
    {
      if (thread_current()->files[fd]->deny_write) 
      {
        file_deny_write(thread_current()->files[fd]);
      }
      length = file_write(cur_file, buffer, size);
      lock_release(&memory);
      printf("mem lock released\n");
      return length;
    }   
  }
}

void seek(int fd, int count, struct intr_frame *f)
{
  struct file *cur = process_get_file(fd);
  if (cur != NULL)
  {
    file_seek(cur, count);
  }
}

void tell(int fd, struct intr_frame *f)
{
  struct file *cur = process_get_file(fd);
  unsigned int location = 0;
  if(cur != NULL)
  {
    location = file_tell(cur);
    f->eax = location;
  }
}

void close(int fd, struct intr_frame *f)
{
  //debug
  //printf("close called\n");
  //printf("thread name: %s, %d\n", thread_current()->name, thread_current()->tid);
  //printf("fd %d\n", fd);

  if ((unsigned int) fd > 131)
    exits(-1, NULL);
  struct file *cur = process_get_file(fd);
  struct thread *cur_thread = thread_current();
  int fd_v = fd; //file descriptor value
  if(cur != NULL)
  {
    file_close(cur);
    cur_thread->files[fd_v] = NULL;
  }
}



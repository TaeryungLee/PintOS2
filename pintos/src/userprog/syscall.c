#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"

tid_t exec_handler(char *filename);
static void syscall_handler(struct intr_frame *);

int write_handler(int fd, char *buffer, size_t size);
int read_handler(int fd, char *buffer, size_t size);
struct file *get_file_from_fd(int fd, struct list *fds);
bool is_valid_user_addr(char *userptr, size_t size, uint32_t *pagedir);


struct semaphore filesys_sema; // lock to control file system access


bool is_valid_user_addr(char* userptr, size_t size, uint32_t* pagedir){
    if(is_kernel_vaddr(userptr) || is_kernel_vaddr(userptr + size - 1)){
        return false;
    }
    if((pagedir_get_page(pagedir, userptr) == NULL) ||
    (pagedir_get_page(pagedir, userptr + size -1) == NULL)){
        return false;
    } else {
        return true;
    }
}

struct file* get_file_from_fd(int fd, struct list* fds){
  struct list_elem *e;
  struct file *target = NULL;
  for (e = list_begin(fds); e != list_tail(fds); e = list_next(e)) {
    if (list_entry(e, struct fd, elem)->fd == fd) {
      target = list_entry(e, struct fd, elem)->file;
      break;
    }
  }
  return target;
}

void syscall_init(void)
{
  sema_init(&filesys_sema, 1);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  char *esp = f->esp;
  struct thread *curr = thread_current();
  struct process *current_process = get_current_process();
  //printf("thread name: %s \n", curr->name);
  if (!is_valid_user_addr(esp, 4, curr->pagedir))
  {
    current_process->exit_code = -1;
    thread_exit();
  }
  int syscall_number = *((int *)esp);
  uint32_t* return_val = &(f->eax);

  //printf("syscall number %d\n", syscall_number);
  int fd;
  switch (syscall_number)
  {
  case SYS_HALT:
    power_off();
    break;
  case SYS_EXIT:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      int exit_code = *((int *)esp + 1);
      current_process->exit_code = exit_code;
      sema_up(&current_process->exit_sema);

      thread_exit();
    }
    
    break;
  case SYS_EXEC:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      char *filename = *((char **)esp + 1);
      if(is_valid_user_addr(filename, 1, curr->pagedir) &&
      is_valid_user_addr(filename, strlen(filename), curr->pagedir)){
        sema_down(&filesys_sema);
        tid_t pid = exec_handler(filename);
        *return_val = pid;
        sema_up(&filesys_sema);
      }
      return;
    }
    break;
  case SYS_WAIT:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      int pid = *((int *)esp + 1);
      *return_val = process_wait(pid);
      return;
    }
    break;
  case SYS_CREATE:
    if(is_valid_user_addr(esp+4, 8, curr->pagedir)){
      char *filename = *((char **)esp + 1);
      unsigned initial_size = *((unsigned *)esp + 2);
      if(is_valid_user_addr(filename, 1, curr->pagedir) &&
        is_valid_user_addr(filename, strlen(filename), curr->pagedir)){ // Do I need to check?
        sema_down(&filesys_sema);
        *return_val = filesys_create(filename, initial_size);
        sema_up(&filesys_sema);
        return;
      }
    }
    break;
  case SYS_REMOVE:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      char *filename = *((char **)esp + 1);
      if(is_valid_user_addr(filename, 1, curr->pagedir) &&
        is_valid_user_addr(filename, strlen(filename), curr->pagedir)){ // Do I need to check?
        sema_down(&filesys_sema);
        *return_val = filesys_remove(filename);
        sema_up(&filesys_sema);
        return;
      }
    }
    break;
  case SYS_OPEN:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      char *filename = *((char **)esp + 1);
      if(is_valid_user_addr(filename, 1, curr->pagedir) &&
        is_valid_user_addr(filename, strlen(filename), curr->pagedir)){ // Do I need to check?
        sema_down(&filesys_sema);
        struct file *opened_file = filesys_open(filename);
        if(opened_file != NULL){
          struct fd *newfd = malloc(sizeof(struct fd));
          if (newfd != NULL)
          {
            newfd->fd = (current_process->lastfd++);
            newfd->file = opened_file;
            list_push_back(&current_process->fds, &newfd->elem);
            *return_val = newfd->fd;
          }
          else
          {
            file_close(opened_file);
            *return_val = -1;
          }
        } else {
          *return_val = -1;
        }
        sema_up(&filesys_sema);
        return;
      }
    }
    break;
  case SYS_FILESIZE:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      int fd = *((int *)esp + 1);
      struct file *target = get_file_from_fd(fd, &current_process->fds);
      if (target == NULL)
      {
        *return_val = -1; //no such fd
      } else{
        sema_down(&filesys_sema);
        *return_val = file_length(target);
        sema_up(&filesys_sema);
      }
      return;
    }
    break;
  case SYS_READ:
    if(is_valid_user_addr(esp + 4, 12, curr->pagedir)){
      fd = *((int *)esp + 1);
      char *buffer = *((char **)esp + 2);
      size_t size = *((size_t *)esp + 3);
      if(is_valid_user_addr(buffer, size, curr->pagedir)){
        *return_val = read_handler(fd, buffer, size);
      } else {
        break;
      }

      return;
    }
    break;
  case SYS_WRITE:
    if(is_valid_user_addr(esp + 4, 12, curr->pagedir)){
      fd = *((int *)esp + 1);
      char *buffer = *((char **)esp + 2);
      size_t size = *((size_t *)esp + 3);
      if (is_valid_user_addr(buffer, size, curr->pagedir))
      {
        *return_val = write_handler(fd, buffer, size);
      }
      else
      {
        break;
      }

      return;
    }
    break;
  case SYS_SEEK:
    if(is_valid_user_addr(esp+4, 8, curr->pagedir)){
      int fd = *((int*)esp + 1);
      unsigned position = *((unsigned *)esp + 2);

      struct file *target = get_file_from_fd(fd, &current_process->fds);

      if(target == NULL){
        return;
      }
      else
      {
        file_seek(target, position);
        return;
      }
    }
    break;
  case SYS_TELL:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      int fd = *((int *)esp + 1);
      
      struct file *target = get_file_from_fd(fd, &current_process->fds);

      if(target == NULL){
        *return_val = -1;
        return;
      }
      else
      {
        *return_val = file_tell(target);
        return;
      }
    }
    break;
  case SYS_CLOSE:
    if(is_valid_user_addr(esp+4, 4, curr->pagedir)){
      int fd = *((int *)esp + 1);
      struct list_elem *e;
      struct fd *target = NULL;
      for (e = list_begin(&current_process->fds); e != list_tail(&current_process->fds); e = list_next(e))
      {
        if (list_entry(e, struct fd, elem)->fd == fd)
        {
          target = list_entry(e, struct fd, elem);
          break;
        }
      }

      if(target == NULL){
        return;
      } else {
        file_close(target->file);
        list_remove(&target->elem);
        free(target);
        return;
      }
    }
    break;
  default:
    printf("system call!\n");
    current_process->exit_code = -1;
    thread_exit();
  }
  current_process->exit_code = -1;
  thread_exit();
}

int write_handler(int fd, char* buffer, size_t size){
  struct process *current_process = get_current_process();
  int written_bytes;
  if (fd == 1)
  {
    int length = strlen(buffer) > size? size : strlen(buffer);
    putbuf(buffer, length);
    return length;
  }
  else
  {
    struct file *target = get_file_from_fd(fd, &current_process->fds); // need to be implemented
    if(target == NULL){
      return -1;
    } else {
        sema_down(&filesys_sema);
        written_bytes = file_write(target, buffer, size);
        sema_up(&filesys_sema);
    }
  }
  return written_bytes;
}

int read_handler(int fd, char* buffer, size_t size){
  struct process *current_process = get_current_process();
  int32_t read_bytes = 0;
  if (fd == 0)
  {
    while(read_bytes < (int)size){
      *buffer = input_getc();
      buffer++;
      read_bytes++;
    }
    
  }
  else
  {
    struct file *target = get_file_from_fd(fd, &current_process->fds);
    
    if (target == NULL)
    {
      return -1;
    } else{
      sema_down(&filesys_sema);
      read_bytes = file_read(target, buffer, size);
      sema_up(&filesys_sema);
    }
  }
  return read_bytes;
}

tid_t exec_handler(char* filename){
  struct thread *curr = thread_current();
  struct process *current_process = get_process_by_pid(curr->tid);
  tid_t pid;

  pid = process_execute(filename);
  if (pid != -1)
  {
    struct process *child = get_process_by_pid(pid);
    if(child->thread == NULL){
      free_process(child);
      pid = -1;
    }
    child->parent_pid = curr->tid;
  }

  return pid;
}

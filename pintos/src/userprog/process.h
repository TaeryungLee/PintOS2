#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
struct process {
    tid_t pid;              //pid = tid
    struct thread *thread;  //thread associated with this process
    struct list_elem elem;  //for process_list
    struct list fds;        //list of file descriptors
    int lastfd;             //the last file descriptor
    tid_t parent_pid;       //process id of the parent
    int exit_code;          //exit_code of the process
    struct semaphore exit_sema; //for wait call to get exit code
    struct semaphore exec_sema; //for process_execute to return
    char *process_name;     //process name
    struct file *execfile;
};

struct fd {
  int fd;
  struct file *file;
  struct list_elem elem;
};
void processsys_init(void);
struct process *get_current_process(void);
struct process *get_process_by_pid(tid_t pid);
int free_process(struct process *target_process);
tid_t process_execute(const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void exits(int exit_code, struct intr_frame *f);

#endif /* userprog/syscall.h */

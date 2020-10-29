#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/page.h"

void syscall_init (void);
void exits(int exit_code, struct intr_frame *f);
struct vm_entry* check(void *addr, int count);

#endif /* userprog/syscall.h */

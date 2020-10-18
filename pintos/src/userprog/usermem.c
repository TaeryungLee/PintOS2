#include "userprog/usermem.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"


bool is_valid_user_addr(void* userptr, size_t size, uint32_t* pagedir){
    if(is_kernel_vaddr(userptr) || is_kernel_vaddr(userptr + size - 1)){
        return false;
    }
    if(lookup_page(pagedir, userptr, false) == NULL){
        return false;
    } else {
        return true;
    }
}

bool is_writable(void* userptr, uint32_t* pagedir){
    if(!is_valid_user_addr(userptr, 4, pagedir)){
        return false;
    } else {
        uint32_t *page = lookup_page(pagedir, userptr, false);
        if ((page & 0x2) != 0){
            return true;
        } else{
            return false;
        }
    }
}
#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

struct buffer_head
{
    bool dirty_flag;                        //해당 entry가 dirty?
    bool valid_flag;                        //해당 entry의 사용여부
    block_sector_t sector_addr;             //해당 entry의 disk sector 주소
    bool clock_bit;                         //clock bit for clock algorithm
    struct lock lock;                       //lock 변수
    void *buffer;                           //buffer cache entry 가리키는 데이터 포인터
}
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
};

bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs);
struct buffer_head *bc_lookup(block_sector_t sector); //버퍼캐시를 순회하면 target sector가 있는지 검색
struct buffer_head *bc_select_victim(void); //버퍼캐시에서 victim 선정, entry head 포인터 반환
void bc_flush_entry(struct buffer_head *p_flush_entry); //인자로 주어진 entry의 dirty비트를 false로 세팅하고 해당 내역 disk로 flush
void bc_flush_all_entries(void); //버퍼캐시를 순회하면서 dirty 비트가 true인 entry를 모두 디스크로 flush
void bc_init(void); //버퍼캐시 초기화
void bc_term(void); //모든 dirty entry flush 및 버퍼캐시 해지

#endif
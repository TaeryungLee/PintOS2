#include <stdio.h>
#include <string.h>
#include "filesys/buffer_cache.h"
#include "threads/synch.h"
#include "devices/block.h"
#include <debug.h>


//buffer cache 전역변수
#define BUFFER_CAHCHE_ENTRY_NB 64
static int *p_buffer_cache;
static struct buffer_head  buffer_head[BUFFER_CAHCHE_ENTRY_NB];
static struct buffer_head *clock_hand;


bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs);
struct buffer_head *bc_lookup(block_sector_t sector); //버퍼캐시를 순회하면 target sector가 있는지 검색
struct buffer_head *bc_select_victim(); //버퍼캐시에서 victim 선정, entry head 포인터 반환
void bc_flush_entry(void); //인자로 주어진 entry의 dirty비트를 false로 세팅하고 해당 내역 disk로 flush
void bc_flush_all_entries(void); //버퍼캐시를 순회하면서 dirty 비트가 true인 entry를 모두 디스크로 flush
void bc_init(void); //버퍼캐시 초기화
void bc_term(void); //모든 dirty entry flush 및 버퍼캐시 해지

//buffer_cache = bh->buffer
bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{
    bool success = false;
    struct buffer_head *bh;
    if(bc_lookup(sector_idx) == NULL)
    {
        bh = bc_select_victim();
        bc_flush_entry(bh);
        bh->valid_flag = true;
        bh->sector_addr = sector_idx;
        block_read(fs_device, sector_idx, bh->buffer);
    }
    memcpy(buffer + bytes_read, bh->buffer + sector_ofs, chunk_size);
    bh->clock_bit = true;
    return success;
}

bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
    bool success = false;
    struct buffer_head *bh;
    if(bc_lookup(sector_idx) == NULL)
    {
        bh = bc_select_victim();
        bc_flush_entry(bh);
        bh->valid_flag = true;
        bh->sector_addr = sector_idx;
        block_read(fs_device, sector_idx, bh->buffer);
    }
    memcpy(bh->buffer + sector_ofs, buffer + bytes_written, chunk_size);
    bh->clock_bit = true;
    bh->diry_flag = true;
    return success;
}

void bc_init(void)
{
    struct buffer_head *bh = buffer_head;
    char cache_array[BUFFER_CAHCHE_ENTRY_NB * BLOCK_SECTOR_SIZE];
    p_buffer_cache = cache_array;
    for(bh ; bh != buffer_head + BUFFER_CAHCHE_ENTRY_NB; bh++)
    {
        p_buffer_cache += BLOCK_SECTOR_SIZE;
        memset(bh, 0, sizeof(struct buffer_head));
        lock_init(&bh->lock);
        bh->buffer = p_buffer_cache;
    }
}

void bc_term(void)
{   
    struct buffer_head *bh = buffer_head;
    lock_acquire(&bh -> lock);
    bc_flush_all_entries();
    lock_release(&bh -> lock);
}

struct buffer_head *bc_select_victim(void)
{
    struct buffer_head *bh = buffer_head;
    for(bh ; bh != buffer_head + BUFFER_CAHCHE_ENTRY_NB; bh++)
    {
        if(bh->clock_bit == false)
        {
            if(bh->dirty_flag == true)
            {
                bc_flush_entry(bh);
            }
        }
        bh->clock_bit = false;
    }
    return bh;
}

struct buffer_head *bc_lookup(block_sector_t sector)
{
    struct buffer_head *bh = buffer_head;
    for(bh ; bh != buffer_head + BUFFER_CAHCHE_ENTRY_NB; bh++)
    {
        if(bh-> sector_addr == sector)
        {
            return bh;
        }
    }

    return NULL;
}

void bc_flush_entry(struct buffer_head *p_flush_entry)
{
    p_flush_entry->dirty_flag = false;
    block_write(fs_device, p_flush_entry->sector_addr, p_flush_entry->buffer);
}

void bc_flush_all_entries(void)
{
    struct buffer_head *bh = buffer_head;
    for(bh ; bh != buffer_head + BUFFER_CAHCHE_ENTRY_NB; bh++)
    {
        bc_flush_entry(bh);
    }
}
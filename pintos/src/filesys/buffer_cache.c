#include <string.h>
#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
//#include "threads/synch.h"
#include "devices/block.h"
#include <debug.h>
#include <stdio.h>

//buffer cache 전역변수
#define BUFFER_CACHE_ENTRY_NB 64
static char p_buffer_cache[BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE];
static struct buffer_head  buffer_head[BUFFER_CACHE_ENTRY_NB];
static struct buffer_head *clock_hand;
//static struct lock cache_lock;

//buffer_cache = bh->buffer
bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{

    struct buffer_head *bh;
    bh = bc_lookup(sector_idx);
    if(bh == NULL)
    {
        bh = bc_select_victim();
        bc_flush_entry(bh);
        bh->valid_flag = true;
        bh->sector_addr = sector_idx;
        bh->dirty_flag = false;
        //lock_release(&cache_lock);
        block_read(fs_device, sector_idx, bh->buffer);
    }
    bh->clock_bit = true;
    //printf("\n 1: %#p, 2: %#p, 3: %d \n", buffer + bytes_read, bh->buffer + sector_ofs, chunk_size);
    memcpy(buffer + bytes_read, bh->buffer + sector_ofs, chunk_size);
    lock_release (&bh->lock);
    return true;
}

bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
    struct buffer_head *bh;
    bh = bc_lookup(sector_idx);
    if(bh == NULL)
    {
        bh = bc_select_victim();
        bc_flush_entry(bh);
        bh->valid_flag = true;
        bh->sector_addr = sector_idx;
        //lock_release(&cache_lock);
        block_read(fs_device, sector_idx, bh->buffer);
    }
    
    bh->clock_bit = true;
    bh->dirty_flag = true;
    memcpy(bh->buffer + sector_ofs, buffer + bytes_written, chunk_size);
    lock_release(&bh->lock);
    return true;
}


void bc_init(void)
{
    struct buffer_head *bh = buffer_head;
    void *cache = p_buffer_cache;
    for(int i=0; i < BUFFER_CACHE_ENTRY_NB; i++)
    {
        //printf("%x", bh);
        memset(bh, 0, sizeof(struct buffer_head));
        lock_init(&bh->lock);
        bh->buffer = cache;
        bh ++;
        cache += BLOCK_SECTOR_SIZE;
    }
    clock_hand = buffer_head;
    //lock_init(&cache_lock);
}

void bc_term(void)
{   
    bc_flush_all_entries();

}

struct buffer_head *bc_select_victim(void)
{

    while(true)
    {        
        for(; clock_hand != buffer_head + BUFFER_CACHE_ENTRY_NB; clock_hand++)
        {
            lock_acquire(&clock_hand->lock);
            if(clock_hand->clock_bit == false)
            {
                return clock_hand++;
            }
            clock_hand->clock_bit = false;
            lock_release(&clock_hand->lock);
        }
        clock_hand = buffer_head;
    }
}

struct buffer_head *bc_lookup(block_sector_t sector)
{
    //lock_acquire(&cache_lock);
    struct buffer_head *bh = buffer_head;
    for(int i=0; i < BUFFER_CACHE_ENTRY_NB; i++)
    {
        if(bh->sector_addr == sector)
        {
            if(bh->valid_flag == true)
            {
                lock_acquire(&bh->lock);
                //lock_release(&cache_lock);
                return bh;
            }
        }
        bh++;
    }
    return NULL;
}

void bc_flush_entry(struct buffer_head *p_flush_entry)
{
    if (p_flush_entry->valid_flag == false)
    {
        return;
    }
    if(p_flush_entry->dirty_flag == false)
    {
        return;
    }
    p_flush_entry->dirty_flag = false;
    block_write(fs_device, p_flush_entry->sector_addr, p_flush_entry->buffer);
}

void bc_flush_all_entries(void)
{
    struct buffer_head *bh = buffer_head;
    for(int i=0; i < BUFFER_CACHE_ENTRY_NB; i++)
    {
        lock_acquire(&bh -> lock);
        bc_flush_entry(bh);
        lock_release(&bh -> lock);
        bh++;
    }
}
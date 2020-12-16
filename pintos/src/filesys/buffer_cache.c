#include <string.h>
#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
//#include "threads/synch.h"
#include "devices/block.h"
#include <debug.h>
#include <stdio.h>

//buffer cache 전역변수
#define BUFFER_CACHE_ENTRY_NB 64
static char p_buffer_cache[BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE];
//static void *p_buffer_cache;
static struct buffer_head  buffer_head[BUFFER_CACHE_ENTRY_NB];
static struct buffer_head *clock_hand;
static struct lock cache_lock;

//buffer_cache = bh->buffer
bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{

    struct buffer_head *bh;
    bh = bc_lookup(sector_idx);
    if(bh == NULL)
    {
        bh = bc_select_victim();
        lock_acquire(&bh->lock);
        bc_flush_entry(bh);
        bh->valid_flag = true;
        bh->sector_addr = sector_idx;
        bh->dirty_flag = false;
        lock_release(&cache_lock);
        block_read(fs_device, sector_idx, bh->buffer);
    }else
    {
        lock_acquire(&bh->lock);
    }
    memcpy(buffer + bytes_read, bh->buffer + sector_ofs, chunk_size);
    bh->clock_bit = true;
    //printf("\n 1: %#p, 2: %#p, 3: %d \n", buffer + bytes_read, bh->buffer + sector_ofs, chunk_size);
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
        lock_acquire(&bh->lock);
        bc_flush_entry(bh);
        bh->valid_flag = true;
        bh->sector_addr = sector_idx;
        lock_release(&cache_lock);
        block_read(fs_device, sector_idx, bh->buffer);
    }else
    {
        lock_acquire(&bh->lock);
    }
    memcpy(bh->buffer + sector_ofs, buffer + bytes_written, chunk_size);
    bh->clock_bit = true;
    bh->dirty_flag = true;
    lock_release(&bh->lock);
    return true;
}


void bc_init(void)
{
    struct buffer_head *bh = buffer_head;
    //void *p_buffer_cache = buffer_cache;
    for(int i=0; i < BUFFER_CACHE_ENTRY_NB; i++)
    {
        //printf("%x", bh);
        memset(bh, 0, sizeof(struct buffer_head));
        //bh = calloc(0, sizeof(struct buffer_head));
        lock_init(&bh->lock);
        //bh->buffer = p_buffer_cache;
        bh->buffer = p_buffer_cache + (i * BLOCK_SECTOR_SIZE);
        bh->dirty_flag = false;
        bh->valid_flag = false;
        bh ++;
        //p_buffer_cache += BLOCK_SECTOR_SIZE;
        if(i == 0)
        {
            clock_hand = bh;
        }
    }
    clock_hand = buffer_head;
    lock_init(&cache_lock);
}

void bc_term(void)
{   
    bc_flush_all_entries();

}

struct buffer_head *bc_select_victim(void)
{
  //  struct buffer_head *ch = clock_hand;
    while(true)
    {        
        while(clock_hand < buffer_head + BUFFER_CACHE_ENTRY_NB)
        {
            lock_acquire(&clock_hand->lock);
            if(clock_hand->clock_bit == false)
            {
                if(clock_hand->dirty_flag == true)
                {
                    //lock_acquire(&clock_hand->lock);
                    block_write(fs_device, clock_hand->sector_addr, clock_hand->buffer);
                    //lock_release(&clock_hand->lock);
                }
                lock_release(&clock_hand->lock);
                return clock_hand;
            }else
            {
                if(clock_hand->dirty_flag == true)
                {
                    block_write(fs_device, clock_hand->sector_addr, clock_hand->buffer);
                }
            }
            clock_hand->clock_bit = false;
            lock_release(&clock_hand->lock);
            clock_hand++;
        }
        clock_hand = buffer_head;
    }
}

struct buffer_head *bc_lookup(block_sector_t sector)
{
    lock_acquire(&cache_lock);
    struct buffer_head *bh = buffer_head;
    for(int i=0; i < BUFFER_CACHE_ENTRY_NB; i++)
    {
        if(bh->sector_addr == sector)
        {
            if(bh->valid_flag == true)
            {
                lock_release(&cache_lock);
                return bh;
            }
        }
        bh++;
    }
    return NULL;
}

void bc_flush_entry(struct buffer_head *p_flush_entry)
{

    if(p_flush_entry->dirty_flag == false)
    {
        return;
    }
    block_write(fs_device, p_flush_entry->sector_addr, p_flush_entry->buffer);
    p_flush_entry->dirty_flag = false;
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
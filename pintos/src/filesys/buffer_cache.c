#include <string.h>
#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
//#include "threads/synch.h"
#include "devices/block.h"
#include <debug.h>

//buffer cache 전역변수
#define BUFFER_CACHE_ENTRY_NB 64
static char p_buffer_cache[BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE];
static struct buffer_head  buffer_head[BUFFER_CACHE_ENTRY_NB];
static struct buffer_head *clock_hand;

//buffer_cache = bh->buffer
bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{

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
    return true;
}

bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
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
    bh->dirty_flag = true;
    return true;
}


void bc_init(void)
{
    struct buffer_head *bh = buffer_head;
    void *cache = p_buffer_cache;
    for(; bh != buffer_head + BUFFER_CACHE_ENTRY_NB; bh++)
    {
        cache += BLOCK_SECTOR_SIZE;
        memset(bh, 0, sizeof(struct buffer_head));
        lock_init(&bh->lock);
        bh->buffer = cache;
    }
    clock_hand = buffer_head;
    lock_init(&buffer_head->lock);
}

void bc_term(void)
{   
    struct buffer_head *bh = buffer_head;
    for(; bh != buffer_head + BUFFER_CACHE_ENTRY_NB; bh++)
    {
        lock_acquire(&bh -> lock);
        bc_flush_all_entries();
        lock_release(&bh -> lock);
    }
}

struct buffer_head *bc_select_victim(void)
{
    struct buffer_head *victim;
    for(; clock_hand != buffer_head + BUFFER_CACHE_ENTRY_NB; clock_hand++)
    {
        if(clock_hand->clock_bit == false)
        {
            if(clock_hand->dirty_flag == false)
            {
                return clock_hand++;
            }
            else
            {
                bc_flush_entry(clock_hand);
                return clock_hand ++;
            }
       
        }
        clock_hand->clock_bit = false;
    }
}

struct buffer_head *bc_lookup(block_sector_t sector)
{
    struct buffer_head *bh = buffer_head;
    for(; bh != buffer_head + BUFFER_CACHE_ENTRY_NB; bh++)
    {
        if(bh-> sector_addr == sector)
        {
            if(bh->valid_flag == true)
            {
                //lock_acquire(&bh->lock);
                return bh;
            }
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
    for(; bh != buffer_head + BUFFER_CACHE_ENTRY_NB; bh++)
    {
        bc_flush_entry(bh);
    }
}
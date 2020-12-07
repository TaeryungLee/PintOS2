#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/buffer_cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//modified4.2
#define INDIRECT_BLOCK_ENTRIES (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))
#define DIRECT_BLOCK_ENTRIES 124

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    //block_sector_t start;               /* First data sector. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    //uint32_t unused[125];               /* Not used. */

    //modified 4.2
    block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];
    block_sector_t indirect_block_sec;
    block_sector_t double_indirect_block_sec;
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    //struct inode_disk data;             /* Inode content. */

    //modified 4.2
    struct lock extend_lock;
  };

//modified 4.2
enum direct_t
{
  NORMAL_DIRECT,
  INDIRECT,
  DOUBLE_INDIRECT,
  OUT_LIMIT
};

//modified 4.2
struct sector_location
{
  int directness;
  int index1;
  int index2;
};

//modified 4.2
struct inode_indirect_block
{
  block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
};

static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk);
static void locate_byte(off_t pos, struct sector_location *sec_loc);
static bool register_sector(struct inode_disk *inode_disk, block_sector_t new_sector, struct sector_location sec_loc);
bool inode_update_file_length(struct inode_disk *inode_disk, off_t start_pos, off_t end_pos);
static void free_inode_sectors(struct inode_disk *inode_disk);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

//modified 4-2
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
  //ASSERT (inode != NULL);
  block_sector_t result_sec;

  if (pos < inode_disk->length)
  {
    struct inode_indirect_block *ind_block;
    struct sector_location sec_loc;
    locate_byte(pos, &sec_loc); //인덱스 블록 offset 계산
    switch(sec_loc.directness)
    {
      case NORMAL_DIRECT:
      {
        result_sec = inode_disk->direct_map_table[sec_loc.index1];
        break;
      }
      case INDIRECT:
      {
        ind_block = (struct inode_indirect_block *) malloc(BLOCK_SECTOR_SIZE);
        if(ind_block)
        {
          bc_read(inode_disk->indirect_block_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0);
          result_sec = ind_block -> map_table[sec_loc.index1];
        }
        else
        {
          result_sec = 0;
        }
        free(ind_block);
        break;
      }
      case DOUBLE_INDIRECT:
      {
        ind_block = (struct inode_indirect_block *) malloc(BLOCK_SECTOR_SIZE);
        block_sector_t temp_sec;
        if(ind_block)
        {
          bc_read(inode_disk->double_indirect_block_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0);
          temp_sec = ind_block->map_table[sec_loc.index2];
          bc_read(temp_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0);
          result_sec = ind_block->map_table[sec_loc.index1];
        }
        else
        {
          result_sec = 0;
        }
        free(ind_block);
        break;
      }
    }
    return result_sec;
  }
    //return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      /*
      if (free_map_allocate (sectors, &disk_inode->start)) 
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 

                //modified 4.1
                //block_write (fs_device, disk_inode->start + i, zeros);
                bc_write (disk_inode->start + i, zeros, 0, BLOCK_SECTOR_SIZE, 0);
            }
          success = true; 
        }*/

      
      //modified 4-2
      if(length > 0)
      {
        off_t start_pos = (off_t) sector;
        inode_update_file_length(disk_inode, start_pos, start_pos + length - 1);
      } 
      bc_write(sector, disk_inode, 0 , BLOCK_SECTOR_SIZE, 0);
      free (disk_inode);
      success = true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;


  //modified 4-2
  //block_read (fs_device, inode->sector, &inode->data);
  lock_init(&inode->extend_lock);
  //bc_read(sector, &inode->data, 0, BLOCK_SECTOR_SIZE, 0);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  struct inode_disk *disk_inode; //modified 4-2
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /*
          free_map_release (inode->sector, 1);
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); */

          //modified 4-2
          get_disk_inode(inode, disk_inode);
          //bc_read(inode->sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
          free_inode_sectors(disk_inode);
          free_map_release(inode->sector, 1);
          //free(disk_inode);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  //modified 4-2
  struct inode_disk *inode_disk;
  get_disk_inode(inode, inode_disk);


  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode_disk, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      /*
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          // Read full sector directly into caller's buffer. 
          //block_read (fs_device, sector_idx, buffer + bytes_read);
          bc_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
        }
      else 
        {
          // Read sector into bounce buffer, then partially copy
          // into caller's buffer.
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      */

      bc_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  struct inode_disk *disk_inode = malloc(sizeof (struct inode_disk)); //modified 4-2


  if (inode->deny_write_cnt)
    return 0;


  //modified 4-2
  if(disk_inode == NULL)
  {
    return 0;
  }
  get_disk_inode(inode, disk_inode);
  lock_acquire(&inode->extend_lock);
  int old_length = disk_inode->length;
  int write_end = offset + size - 1;

  if(write_end > old_length - 1)
  {
    inode_update_file_length(disk_inode, offset, write_end);
  }
  lock_release(&inode->extend_lock);


  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      /*
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          // Write full sector directly to disk. 
          //block_write (fs_device, sector_idx, buffer + bytes_written);
          bc_write(sector_idx, buffer, bytes_written, chunk_size, sector_ofs);
        }
      else 
        {
          // We need a bounce buffer. 
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          // If the sector contains data before or after the chunk
          // we're writing, then we need to read in the sector
          // first.  Otherwise we start with a sector of all zeros. 
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }
      */

    //modified 4-1  
    bc_write(sector_idx, buffer, bytes_written, chunk_size, sector_ofs); 
    
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  
  //modified 4-2
    bc_write(inode->sector, disk_inode, 0 , BLOCK_SECTOR_SIZE, 0);

  //free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{ 
  struct inode_disk *inode_disk;
  bc_read(inode->sector, inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  return inode_disk->length;
}


//below from here, modified 4.2
static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk)
{
  return bc_read(inode->sector, inode_disk, 0, sizeof(struct inode_disk), 0);
}

static void locate_byte(off_t pos, struct sector_location *sec_loc)
{
  off_t pos_sector = pos / BLOCK_SECTOR_SIZE;

  //direct
  if(pos_sector < DIRECT_BLOCK_ENTRIES)
  {
    sec_loc -> directness = NORMAL_DIRECT;
    sec_loc -> index1 = pos_sector;
  }
  else if(pos_sector < (off_t)(DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES))
  {
    sec_loc -> directness = INDIRECT;
    sec_loc -> index1 = pos_sector;
  }
  else if(pos_sector < (off_t)(DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * (INDIRECT_BLOCK_ENTRIES + 1)))
  {
    sec_loc -> directness = DOUBLE_INDIRECT;
    sec_loc -> index2 = pos_sector / INDIRECT_BLOCK_ENTRIES;
    sec_loc -> index1 = pos_sector % INDIRECT_BLOCK_ENTRIES; //**check
    
  }
  else
  {
    sec_loc->directness = OUT_LIMIT;
  }
}

//uncompleted
static bool register_sector(struct inode_disk *inode_disk, block_sector_t new_sector, struct sector_location sec_loc)
{
  struct inode_indirect_block *new_block;

  switch(sec_loc.directness)
  {
    case NORMAL_DIRECT:
    {
      inode_disk -> direct_map_table[sec_loc.index1] = new_sector;
      break;
    }
    case INDIRECT:
    {
      new_block = malloc(BLOCK_SECTOR_SIZE);
      if(new_block == NULL)
      {
        return false;
      }  
      bc_read(inode_disk->indirect_block_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      new_block->map_table[sec_loc.index1] = new_sector;
      bc_write(inode_disk->indirect_block_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      break;
    }
    case DOUBLE_INDIRECT:
    {
      struct inode_indirect_block *ind_block_1;
      struct inode_indirect_block *ind_block_2;
      block_sector_t temp_sec;

      new_block = malloc(BLOCK_SECTOR_SIZE);
      if(new_block == NULL)
      {
        return false;
      }
      bc_read(inode_disk->double_indirect_block_sec, ind_block_1, 0, sizeof(struct inode_indirect_block), 0);
      temp_sec = ind_block_1->map_table[sec_loc.index2];
      bc_read(temp_sec, ind_block_2, 0, sizeof(struct inode_indirect_block), 0);
      ind_block_2->map_table[sec_loc.index1] = new_sector;
      bc_write(inode_disk->double_indirect_block_sec, ind_block_1, 0, sizeof(struct inode_indirect_block), 0);
      bc_write(temp_sec, ind_block_2, 0, sizeof(struct inode_indirect_block), 0);
      break;
    }
    default:
      return false;
  }
  free(new_block);
  return false;
}

bool inode_update_file_length(struct inode_disk *inode_disk, off_t start_pos, off_t end_pos)
{
  static char zeroes[BLOCK_SECTOR_SIZE];
  off_t size_old = inode_disk->length;
  off_t size = end_pos - start_pos;
  off_t offset = start_pos;

/*
  off_t inode_left = size_old - offset;
  int sector_left = BLOCK_SECTOR_SIZE - (offset % BLOCK_SECTOR_SIZE);
  int min_left = inode_left < sector_left ? inode_left : sector_left;
  int chunk_size = size < min_left ? size : min_left;*/

  int chunk_size = BLOCK_SECTOR_SIZE;
  if(chunk_size < 0)
  {
    return false;
  }

  if(size_old < size)
  {
    return false;
  }

  while(size > 0)
  {
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    if(sector_ofs > 0) //오프셋이 0보다 큰 경우, 이미 할당된 블록
    {
      continue;
    } 
    else
    {
      block_sector_t sector_idx = byte_to_sector(inode_disk, offset);
      struct sector_location sec_loc;
      if(free_map_allocate(1, &sector_idx))
      {
        locate_byte(offset, &sec_loc);
        register_sector(inode_disk, sector_idx, sec_loc);
      }
      else
      {
        //free(zeroes);
        return false;
      }
      bc_write(sector_idx, zeroes, 0, BLOCK_SECTOR_SIZE, 0);  
    }
    size -= chunk_size;
    offset += chunk_size;
  }
  //free(zeroes);
  return true;
}

static void free_inode_sectors(struct inode_disk *inode_disk)
{
  struct inode_indirect_block *ind_block_1;
  struct inode_indirect_block *ind_block_2;
  if(inode_disk -> double_indirect_block_sec > 0)
  {
    bc_read(inode_disk->indirect_block_sec, ind_block_1, 0, sizeof(struct inode_indirect_block), 0);
    int i = 0;
    while(ind_block_1->map_table[i] > 0)
    {
      bc_read(inode_disk->double_indirect_block_sec, ind_block_2, 0, sizeof(struct inode_indirect_block), 0);
      int j = 0;
      while(ind_block_2->map_table[j] > 0)
      {
        free_map_release(ind_block_2->map_table[j], 1); //디스크 블록 free
        j++;
      }
      free_map_release(inode_disk->double_indirect_block_sec, 1); //2차 인덱스 블록 free
      i++;
    }
    free_map_release(inode_disk->indirect_block_sec, 1); //1차 인덱스 블록 free
  }
  else if(inode_disk->indirect_block_sec > 0)
  {
    bc_read(inode_disk->indirect_block_sec, ind_block_1, 0, sizeof(struct inode_indirect_block), 0);
    int i = 0;
    while(ind_block_1->map_table[i] > 0)
    {
      free_map_release(ind_block_2->map_table[i], 1);
      i++;
    }
    free_map_release(inode_disk->indirect_block_sec, 1);
  }
  else
  {
    int i = 0;
    while(inode_disk->direct_map_table[i])
    {
      free_map_release(inode_disk->direct_map_table[i], 1);
      i++;
    }
  }
}
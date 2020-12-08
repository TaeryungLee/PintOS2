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
#include <stdio.h>

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
bool inode_update_file_length(struct inode_disk *inode_disk, off_t length, off_t new_length);
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
    block_sector_t temp_sec;
    block_sector_t error = (block_sector_t) -1;

    switch(sec_loc.directness)
    {
      case NORMAL_DIRECT:
      {
        result_sec = inode_disk->direct_map_table[sec_loc.index1];
        break;
      }
      case INDIRECT:
      {
        ind_block = malloc(sizeof (struct inode_indirect_block));
        if(inode_disk->indirect_block_sec != error)
        {
          bc_read(inode_disk->indirect_block_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0);
          result_sec = ind_block -> map_table[sec_loc.index1];          
        }
        else
        {
          result_sec = -1;
        }
        free(ind_block);
        break;
      }
      case DOUBLE_INDIRECT:
      {
        ind_block = malloc(sizeof (struct inode_indirect_block));

        if(inode_disk->double_indirect_block_sec != error)
        {
          bc_read(inode_disk->double_indirect_block_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0);
          temp_sec = ind_block->map_table[sec_loc.index2];          
          bc_read(temp_sec, ind_block, 0, sizeof(struct inode_indirect_block), 0);
          result_sec = ind_block->map_table[sec_loc.index1];
        }
        else
        {
          result_sec = -1;
        }
        free(ind_block);
        break;
      }
    }
    return result_sec;
  }

  else
    return -1;
}
/*
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
  ASSERT (inode_disk != NULL);

  // 테이블을 메모리에서 다루기 위한 변수입니다.
  struct inode_indirect_block ind_block;
  // 테이블의 유형과 테이블에서의 위치를 나타냅니다.
  struct sector_location sec_loc;

  // 현재 살펴보고 있는 테이블의 섹터 번호입니다.
  // 실행 흐름에 따라서 한 단계 테이블 또는 두 단계 테이블을 가리킵니다.
  block_sector_t table_sector = inode_disk->indirect_block_sec;

  if ((pos < inode_disk->length) == false)
    return -1;

  // 바이트 단위 위치에서, 테이블 유형과 테이블에서의 위치를 얻습니다.
  locate_byte (pos, &sec_loc);
  switch (sec_loc.directness)
    {
      case NORMAL_DIRECT:
        // 바로 가져옵니다.
        return inode_disk->direct_map_table[sec_loc.index1];
      case DOUBLE_INDIRECT:
        // 한 번 참조합니다.
        if (inode_disk->double_indirect_block_sec == (block_sector_t) -1)
          return -1;
        if (!bc_read (inode_disk->double_indirect_block_sec, &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          return -1;
        // 아직 수행하지 않은 한 번의 참조는 아래에서 계속 수행합니다.
        table_sector = ind_block.map_table[sec_loc.index2];
      case INDIRECT:
        if (table_sector == (block_sector_t) -1)
          return -1;
        if (!bc_read (table_sector, &ind_block, 0, sizeof (struct inode_indirect_block), 0))
          return -1;
        return ind_block.map_table[sec_loc.index1];
      default:
        return -1;
    }
  // 여기에 도달할 수 없습니다.
  NOT_REACHED ();
}
*/

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
      //size_t sectors = bytes_to_sectors (length);
      memset(disk_inode, -1, sizeof( struct inode_disk));
      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;
      //printf("inode_length: %d \n", disk_inode->length);
      //modified 4-2
      if(length > 0)
      {
        off_t start_pos = (off_t) sector;
        inode_update_file_length(disk_inode, disk_inode->length, length);
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
  lock_init(&inode->extend_lock);
  //block_read (fs_device, inode->sector, &inode->data);
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
  struct inode_disk *inode_disk = malloc(sizeof (struct inode_disk));
  //printf("%d", sizeof(struct inode_disk));
  lock_acquire(&inode->extend_lock);
  get_disk_inode(inode, inode_disk);


  while (size > 0) 
    {
      // Disk sector to read, starting byte offset within sector. 
      block_sector_t sector_idx = byte_to_sector (inode_disk, offset);
      lock_release(&inode->extend_lock);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;


      // Bytes left in inode, bytes left in sector, lesser of the two.
      off_t inode_left = inode_disk->length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      // Number of bytes to actually copy out of this sector.
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
      {
        lock_acquire(&inode->extend_lock);
        break;
      }

      bc_read(sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
      // Advance.
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
      lock_acquire(&inode->extend_lock);
    }
  free (bounce);
  lock_release(&inode->extend_lock);
  return bytes_read;
}

/*
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  struct inode_disk inode_disk;
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  // 먼저 락을 취득합니다.
  lock_acquire (&inode->extend_lock);

  // 디스크 아이노드를 버퍼 캐시에서 읽습니다.
  get_disk_inode (inode, &inode_disk);

  while (size > 0)
    {
      //Disk sector to read, starting byte offset within sector. 

      // 경쟁적으로 테이블에 접근할 수 있으므로 락을 취득한 상태에서 수행합니다.
      block_sector_t sector_idx = byte_to_sector (&inode_disk, offset);
      lock_release (&inode->extend_lock);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      //Bytes left in inode, bytes left in sector, lesser of the two. 
      off_t inode_left = inode_disk.length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      // Number of bytes to actually copy out of this sector. 
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        {
          // 루프의 시작 직전과 종료 직후에서 락을 취득한 상태로 유지합니다.
          lock_acquire (&inode->extend_lock);
          break;
        }

      // 섹터 번호가 정해진 이후, 데이터 읽기 작업은 락을 해제한 상태에서 수행해도 괜찮습니다.
      bc_read (sector_idx, buffer, bytes_read, chunk_size, sector_ofs);

      // Advance. 
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;

      // 다음 byte_to_sector 작업 이전에, 락을 미리 취득합니다.
      lock_acquire (&inode->extend_lock);
    }
  // 마지막으로 락을 해제합니다.
  lock_release (&inode->extend_lock);
  return bytes_read;
}*/


/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
/*
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;
  struct inode_disk *disk_inode = malloc(sizeof (struct inode_disk)); //modified 4.2
  
  if (inode->deny_write_cnt)
    return 0;


  //modified 4.2
  lock_acquire(&inode->extend_lock);
  get_disk_inode(inode, disk_inode);
  int old_length = disk_inode->length;
  int write_end = offset + size;

  if(write_end > old_length)
  {
    inode_update_file_length(disk_inode, old_length, write_end);
  }


  while (size > 0) 
    {
      // Sector to write, starting byte offset within sector.
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      // Bytes left in inode, bytes left in sector, lesser of the two.
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      // Number of bytes to actually write into this sector.
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      //modified 4-1  
      bc_write(sector_idx, buffer, bytes_written, chunk_size, sector_ofs); 
    
      // Advance. 
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  lock_release(&inode->extend_lock);
  //modified 4-2
  //bc_write(inode->sector, disk_inode, 0 , BLOCK_SECTOR_SIZE, 0);

  //free (bounce);

  return bytes_written;
}
*/

off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  struct inode_disk inode_disk;
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  // 먼저 락을 취득합니다.
  lock_acquire (&inode->extend_lock);

  // 디스크 아이노드를 버퍼 캐시에서 읽습니다.
  get_disk_inode (inode, &inode_disk);
  
  if (inode_disk.length < offset + size)
    {
      // 크기 변화가 이 쓰기로 인하여 발생됩니다.
      if (!inode_update_file_length (&inode_disk, inode_disk.length, offset + size))
        NOT_REACHED ();
      // 디스크 아이노드는 바로 앞의 수행에서 잠재적으로 변경되었습니다.
      bc_write (inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
    }
  
  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */

      // 경쟁적으로 테이블에 접근할 수 있으므로 락을 취득한 상태에서 수행합니다.
      block_sector_t sector_idx = byte_to_sector (&inode_disk, offset);
      lock_release (&inode->extend_lock);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
  
      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_disk.length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        {
          // 루프의 시작 직전과 종료 직후에서 락을 취득한 상태로 유지합니다.
          lock_acquire (&inode->extend_lock);
          break;
        }

      // 섹터 번호가 정해진 이후, 데이터 쓰기 작업은 락을 해제한 상태에서 수행해도 괜찮습니다.
      bc_write (sector_idx, (void *)buffer, bytes_written, chunk_size, sector_ofs);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      // 다음 byte_to_sector 작업 이전에, 락을 미리 취득합니다.
      lock_acquire (&inode->extend_lock);
    }
  // 마지막으로 락을 해제합니다.
  lock_release (&inode->extend_lock);
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
  struct inode_disk *inode_disk = malloc(sizeof (struct inode_disk));
  bc_read(inode->sector, inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
  return inode_disk->length;
}


//below from here, modified 4.2
static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk)
{
  return bc_read(inode->sector, inode_disk, 0, sizeof(struct inode_disk), 0);
}

/*
static void locate_byte(off_t pos, struct sector_location *sec_loc)
{
  off_t pos_sector = pos / BLOCK_SECTOR_SIZE;

  //direct
  if(pos_sector < DIRECT_BLOCK_ENTRIES)
  {
    sec_loc -> directness = NORMAL_DIRECT;
    sec_loc -> index1 = pos_sector;
  }
  else if(pos_sector < DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)
  {
    pos_sector = pos_sector - DIRECT_BLOCK_ENTRIES;
    sec_loc -> directness = INDIRECT;
    sec_loc -> index1 = pos_sector;
  }
  else if(pos_sector < (2 * DIRECT_BLOCK_ENTRIES) + (INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES))
  {
    pos_sector = pos_sector - (2 * DIRECT_BLOCK_ENTRIES);
    sec_loc -> directness = DOUBLE_INDIRECT;
    sec_loc -> index2 = pos_sector / INDIRECT_BLOCK_ENTRIES;
    sec_loc -> index1 = pos_sector % INDIRECT_BLOCK_ENTRIES; //**check
    
  }
  else
  {
    sec_loc->directness = OUT_LIMIT;
  }
}*/


static void
locate_byte (off_t pos, struct sector_location *sec_loc)
{
  // 바이트 단위 거리를 블럭 단위로 변환합니다.
  off_t pos_sector = pos / BLOCK_SECTOR_SIZE;

  // 기본값을 오류로 설정
  sec_loc->directness = OUT_LIMIT;

  if (pos_sector < DIRECT_BLOCK_ENTRIES)
    {
      // 디스크 아이노드에서 직접 참조
      sec_loc->directness = NORMAL_DIRECT;
      sec_loc->index1 = pos_sector;
    }
  else if ((pos_sector -= DIRECT_BLOCK_ENTRIES) < INDIRECT_BLOCK_ENTRIES)
    {
      // 한 단계 참조
      sec_loc->directness = INDIRECT;
      sec_loc->index1 = pos_sector;
    }
  else if ((pos_sector -= INDIRECT_BLOCK_ENTRIES) < INDIRECT_BLOCK_ENTRIES * INDIRECT_BLOCK_ENTRIES)
    {
      // 두 단계 참조
      sec_loc->directness = DOUBLE_INDIRECT;
      // index2 이후 index1 순서입니다. 이 순서는 다른 부분의 코드를 간단하게 합니다.
      sec_loc->index2 = pos_sector / INDIRECT_BLOCK_ENTRIES;
      sec_loc->index1 = pos_sector % INDIRECT_BLOCK_ENTRIES;
    }
}



static bool register_sector(struct inode_disk *inode_disk, block_sector_t new_sector, struct sector_location sec_loc)
{
  struct inode_indirect_block *new_block;
  struct inode_indirect_block *new_block_double;
  block_sector_t error = (block_sector_t) -1;
  switch(sec_loc.directness)
  {
    case NORMAL_DIRECT:
    {
      inode_disk -> direct_map_table[sec_loc.index1] = new_sector;
      return true;
    }
    case INDIRECT:
    {
      new_block = malloc(sizeof (struct inode_indirect_block));
      if(inode_disk->indirect_block_sec == error)
      {
        if(free_map_allocate(1, &inode_disk->indirect_block_sec) == false)
        {
          return false;
        }
        memset(new_block, -1, sizeof(struct inode_indirect_block));
      }
      else
      {
        bc_read(inode_disk->indirect_block_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      }
      
      
      new_block->map_table[sec_loc.index1] = new_sector;
      bc_write(inode_disk->indirect_block_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      break;
    }
    case DOUBLE_INDIRECT:
    {

      block_sector_t temp_sec;
      new_block_double = malloc(sizeof (struct inode_indirect_block));
      new_block = malloc(sizeof (struct inode_indirect_block));
      if(inode_disk->double_indirect_block_sec == error)
      {
        if(free_map_allocate(1, &inode_disk->double_indirect_block_sec) == false)
        {
          return false;
        }
        memset(new_block, -1, sizeof(struct inode_indirect_block));
        memset(new_block_double, -1, sizeof(struct inode_indirect_block));

      }
      else
      {
        bc_read(inode_disk->double_indirect_block_sec, new_block_double, 0, sizeof(struct inode_indirect_block), 0);
        temp_sec = new_block_double->map_table[sec_loc.index2];
        bc_read(temp_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      }
      
      //bc_read(inode_disk->double_indirect_block_sec, new_block_double, 0, sizeof(struct inode_indirect_block), 0);
      //temp_sec = new_block_double->map_table[sec_loc.index2];
      //bc_read(temp_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      new_block->map_table[sec_loc.index1] = new_sector;
      bc_write(inode_disk->double_indirect_block_sec, new_block_double, 0, sizeof(struct inode_indirect_block), 0);
      bc_write(temp_sec, new_block, 0, sizeof(struct inode_indirect_block), 0);
      free(new_block_double);
      break;
    }
    default:
      return false;
  }
  free(new_block);
  return true;
}

/*
static bool
register_sector (struct inode_disk *inode_disk,
                 block_sector_t new_sector,
                 struct sector_location sec_loc)
{
  struct inode_indirect_block first_block, second_block;

  // 두 단계 참조인 경우, 첫 번째 참조 테이블이 갱신되어야 하는지를 나타내는 플래그입니다.
  bool first_dirty = false;

  // 참조 테이블의 섹터 번호를 저장하고 있는 변수에 대한 포인터입니다.
  // 실행 흐름에 따라서 다양한 장소를 가리킵니다.
  block_sector_t *table_sector = &inode_disk->indirect_block_sec;

  switch (sec_loc.directness)
    {
    case NORMAL_DIRECT:
      // 디스크 아이노드 직접 참조입니다.
      inode_disk->direct_map_table[sec_loc.index1] = new_sector;
      return true;
    case DOUBLE_INDIRECT:
      // 두 단계 참조가 일어납니다.
      table_sector = &inode_disk->double_indirect_block_sec;
      if (*table_sector == (block_sector_t) -1)
        {
          // 두 단계 참조 테이블을 처음으로 사용하는 경우입니다.
          if (!free_map_allocate (1, table_sector))
            return false;
          // unsigned 정수의 가장 큰 값을 유효하지 않은 섹터 번호를 나타내기 위하여 예약하기로 합니다.
          memset (&first_block, -1, sizeof (struct inode_indirect_block));
        }
      else
        {
          // 두 단계 참조 테이블이 이미 존재하는 경우입니다. 테이블을 읽습니다.
          if (!bc_read (*table_sector, &first_block, 0, sizeof (struct inode_indirect_block), 0))
            return false;
        }
      // 메모리에 읽은 두 단계 테이블에서, 다음 테이블에 대한 섹터 번호를 저장하고 있는 변수에 대한 포인터
      table_sector = &first_block.map_table[sec_loc.index2];

      // 더러움 플래그가 활성화되는 경우는 마지막 단계 테이블이 할당되지 않은 경우입니다.
      // 마지막 단계 테이블의 섹터 번호는 첫 단계 테이블에 저장되므로 첫 단계 테이블을 다시 쓸 필요가 있기 때문입니다.
      if (*table_sector == (block_sector_t) -1)
          first_dirty = true;
    case INDIRECT:
      // 여기에서 table_sector는 한 단계 테이블의 유일한 테이블 또는 두 단계 테이블의 마지막 테이블을 가리킵니다.
      if (*table_sector == (block_sector_t) -1)
        {
          // 테이블이 없는 경우에 할당하고
          if (!free_map_allocate (1, table_sector))
            return false;
          memset (&second_block, -1, sizeof (struct inode_indirect_block));
        }
      else
        {
          // 테이블이 있다면 읽습니다.
          if (!bc_read (*table_sector, &second_block, 0, sizeof (struct inode_indirect_block), 0))
            return false;
        }
      if (second_block.map_table[sec_loc.index1] == (block_sector_t) -1)
        second_block.map_table[sec_loc.index1] = new_sector;
      else
        // 여기에 도달할 수 없습니다.
        NOT_REACHED ();

      // 첫 단계 테이블이 더러운 경우에 다시 씁니다.
      if (first_dirty)
        {
          if (!bc_write (inode_disk->double_indirect_block_sec, &first_block, 0, sizeof (struct inode_indirect_block), 0))
            return false;
        }
      // 마지막 단계 테이블은 항상 다시 씁니다.
      if (!bc_write (*table_sector, &second_block, 0, sizeof (struct inode_indirect_block), 0))
        return false;
      return true;
    default:
      return false;
    }
  NOT_REACHED ();
}
*/

/*
bool inode_update_file_length(struct inode_disk *inode_disk, off_t start_pos, off_t end_pos)
{
  static char zeroes[BLOCK_SECTOR_SIZE];
  off_t size_old = inode_disk->length;
  off_t size = end_pos - start_pos;
  off_t offset = start_pos;


  //off_t inode_left = size_old - offset;
  //int sector_left = BLOCK_SECTOR_SIZE - (offset % BLOCK_SECTOR_SIZE);
  //int min_left = inode_left < sector_left ? inode_left : sector_left;
  //int chunk_size = size < min_left ? size : min_left;

  int chunk_size = BLOCK_SECTOR_SIZE;
  if(chunk_size < 0)
  {
    return false;
  }
  printf("size:%d  size_old:%d", size, size_old);
  if(size_old > size)
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
}*/

//need to change
bool inode_update_file_length(struct inode_disk *inode_disk, off_t length, off_t new_length)
{
  static char zeroes[BLOCK_SECTOR_SIZE];

  if(length == new_length)
  {
    return true;
  }
  if(length > new_length)
  {
    return false;
  }

  inode_disk->length = new_length;
  new_length--;

  //printf("length=%d, new_length=%d \n", length, new_length);
  length = length / BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE;
  new_length = new_length /BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE;
  //printf("length=%d, new_length=%d \n", length, new_length);
  for (; length <= new_length; length += BLOCK_SECTOR_SIZE)
    {
      struct sector_location sec_loc;

      block_sector_t sector = byte_to_sector (inode_disk, length);
      
      if (sector != (block_sector_t) -1)
      {
        continue;
      }
      
      if (!free_map_allocate (1, &sector))
      {
        //printf("1\n");
        return false;
      }
      locate_byte (length, &sec_loc);
      if (!register_sector (inode_disk, sector, sec_loc))
      {
        //printf("2 \n");
        return false;
      }
      if (!bc_write (sector, zeroes, 0, BLOCK_SECTOR_SIZE, 0))
      {
        //printf("3 \n");
        return false; 
      }
    }
  //printf("%d \n", inode_disk->length);
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

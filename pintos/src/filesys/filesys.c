#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer_cache.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

//modified 4.3
struct dir* parse_path(char *path_name, char *file_name);
bool filesys_create_dir(const char* name);


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");
  bc_init();
  inode_init ();
  free_map_init ();


  if (format) 
    do_format ();

  free_map_open ();

  dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  bc_term();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char *cp_name = name;
  char* file_name;
  struct dir *dir = parse_path(cp_name, file_name);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, (uint32_t)0)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  //modified 4.3
  char *cp_name = name;
  char *file_name;
  struct dir *dir = parse_path(cp_name, file_name);
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  //modified 4.3
  char *cp_name = name;
  char *file_name;
  struct dir *dir = parse_path(cp_name, file_name);
  //bool success = dir != NULL && dir_remove (dir, name);
  //dir_close (dir); 
  struct inode *inode_cur;
  bool success = false;
  dir_lookup(dir, file_name, &inode_cur);
  char* temp_name[NAME_MAX+1];
  struct dir *dir_cur = dir_open(inode_cur);
  if(inode_is_dir(inode_cur) == true)
  {    
    if(dir_readdir(dir_cur, temp_name) == false)
    {
      success = dir_remove(file_name);
    }
  }
  else
  {
    success = dir_remove(file_name);
  }
  dir_remove(dir, file_name);
  dir_close(dir);
  

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

//modified 4.3
struct dir* parse_path(char *path_name, char *file_name)
{
  struct dir *dir;
  struct inode *inode;
  //int max_len = 512;
  if(path_name == NULL || file_name == NULL)
  {
    goto fail;
  }

  if(strlen(path_name) == 0)
  {
    return NULL;
  }
  char path[512];
  strlcpy(path, path_name, 512);
  if(path[0] == "/")
  {
    dir_open_root();
  }else
  {
    struct dir *dir_temp = thread_current()->cur_dir;
    dir = dir_reopen(dir_temp);
  }
  

  char *token;
  char *next_token;
  char *save_ptr;

  token = strtok_r(path_name, "/", &save_ptr);
  next_token = strtok_r(NULL, "/", &save_ptr);
  while(token != NULL && next_token != NULL)
  {

    if(dir_lookup(dir, token, &inode) == true)
    {
      if(inode_is_dir(inode) == true)
      {
        dir_close(dir);
        dir = dir_open(inode);
      }
    }else
    {
      dir_close(dir);
      return NULL;
    }
    token = next_token;
    next_token = strtok_r(NULL, "/", &save_ptr);
  }
  strlcpy(file_name, token, strlen(token));
  return dir;
}

bool filesys_create_dir(const char* name)
{
  char *cp_name = name;
  char *file_name;
  struct dir *dir = parse_path(cp_name, file_name);
  block_sector_t inode_sector = 0;

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_create(inode_sector, 16)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  
  if(success == true)
  {
    struct inode *inode_new = inode_open(inode_sector);
    struct dir *dir_new = dir_open(inode_new);
    dir_add(dir_new, ".", inode_sector);
    dir_add(dir_new, "..", inode_sector);
    dir_close(dir_new);
  }
  dir_close(dir);
  return success;
}
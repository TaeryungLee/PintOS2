#include "page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include <string.h>
#include <list.h>
#include <hash.h>

unsigned vm_hash_func (const struct hash_elem *e, void *aux);
bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);

// use hash_init() to initialize hash table
// bool hash_init (struct hash *h, hash_hash_func *, hash_less_func *, void *aux)
// h: hash table to initialize
// hash_hash_func: function pointer to fetch hash value
// hash_less_func: function pointer to compare hash value
void vm_init (struct hash *vm)
{
  ASSERT (vm != NULL);

	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

// use hash_entry() to use hash element to find corresponding stored vm_entry structure
// hash_entry(HASH_ELEM, STRUCT, MEMBER)
// use hash_int() to fetch hash value
unsigned vm_hash_func (const struct hash_elem *e, void *aux)
{
	ASSERT (e != NULL);
	struct vm_entry *vme;
	int vaddr;
	vme = hash_entry(e, struct vm_entry, elem);
	vaddr = vme->vaddr;

	return hash_int(vaddr);
}

// use hash_entry() to use hash element to find corresponding stored vm_entry structure
// compare vaddr, return true if b has larger vaddr, false otherwise
bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
	ASSERT (a != NULL);
  ASSERT (b != NULL);
	struct vm_entry *vme_a;
	struct vm_entry *vme_b;

	vme_a = hash_entry(a, struct vm_entry, elem);
	vme_b = hash_entry(b, struct vm_entry, elem);

	int vaddr_a = vme_a->vaddr;
	int vaddr_b = vme_b->vaddr;
	return vaddr_a < vaddr_b;
}

// use hash_insert() to insert vm_entry into hash table
// struct hash_elem *hash_insert (struct hash *, struct hash_elem *);
// return true if success, otherwise false
bool insert_vme (struct hash *vm, struct vm_entry *vme)
{
	ASSERT (vm != NULL);
  ASSERT (vme != NULL);
  ASSERT (pg_ofs (vme->vaddr) == 0);
	struct hash_elem* result;
	struct hash_elem elem = vme->elem;
	result = hash_insert(vm, &elem);

	if (result == NULL)
		return false;
	return true;
}

// use hash_delete() to remove vm_entry from hash table
// struct hash_elem *hash_delete (struct hash *, struct hash_elem *);
// return true if element has found in hash table, otherwise false
bool delete_vme (struct hash *vm, struct vm_entry *vme)
{
  ASSERT (vm != NULL);
  ASSERT (vme != NULL);
	struct hash_elem* result;
	struct hash_elem elem = vme->elem;
	result = hash_delete(vm, &elem);
	free(vme);

	if (result == NULL)
		return false;
	return true;
}

// use pg_round_down() to find page address
// use hash_find() to fetch hash_elem
// struct hash_elem *hash_find (struct hash *, struct hash_elem *);
// if doesn't exist, return NULL
// use hash_entry() to return stored vm_entry structure
struct vm_entry *find_vme(void *vaddr)
{
	void* page;
	struct vm_entry *vme;
	struct vm_entry *vme_found;
	struct hash_elem *elem;
	struct thread *cur = thread_current();

	vme = calloc(1, sizeof(struct vm_entry));
	page = pg_round_down(vaddr);

	vme->vaddr = page;
	elem = hash_find(&cur->vm, &vme->elem);

	if (elem == NULL)
		return NULL;

	vme_found = hash_entry(elem, struct vm_entry, elem);
	return vme_found;
}

void vm_destructor_func (struct hash_elem *e, void* aux);

// use hash_destroy() to remove hash table and vm_entries
// void hash_destroy (struct hash *h, hash_action_func *destructor)
// helping destructor function vm_destructor_func additionally designed

void vm_destroy (struct hash *vm)
{
	ASSERT (vm != NULL);
	hash_destroy(vm, vm_destructor_func);
}

// hash_destroy calls destructor: destructor (hash_elem, h->aux)
// in hash.c, description is given as:
// DESTRUCTOR may, if appropriate, deallocate the memory used by the hash element.
void vm_destructor_func (struct hash_elem *e, void* aux)
{
	ASSERT (e != NULL);
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
  free(vme);
}

// size can be bigger than PGSIZE
// use check() if it is user address, and get vm_entry
// check vm_entry exists, and it is writable
// do above for buffer to buffer+size
void check_valid_buffer (void *buffer, unsigned size, bool to_write)
{

  for(int i=0; i < size; i++)
  {
  	// check address and get vm_entry
    struct vm_entry* vme = check((void *) (buffer + i), 1);

    // is writable
    if ((!vme->writable) && to_write)
    	exits(-1, NULL);
  }
}

// use check() if it is user address
// check vm_entry exists
void check_valid_string (const void *str)
{
	struct vm_entry * vme = check(str, 1);
	if (vme == NULL)
		exits(-1, NULL);
}

// load page in disk onto physical memory
// off_t file_read_at (struct file *file, void *buffer, off_t size, off_t file_ofs)
// file_read_at reads SIZE bytes from FILE into BUFFER, starting at offset FILE_OFS in the file
// returns number of bytes read
bool load_file (void* kaddr, struct vm_entry *vme)
{
  ASSERT (kaddr != NULL);
  ASSERT (vme != NULL);
  ASSERT (vme->type == VM_BIN);
	// try to read from file
	int read_bytes = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);

	// if read fails, return false
	if ((int)vme->read_bytes != read_bytes)
		return false;

	// add zero paddings into remaining area of page
	memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	return true;
}




























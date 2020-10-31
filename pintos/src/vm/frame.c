#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

struct list lru_list;
struct lock lru_list_lock;
struct list_elem *lru_clock;

void lru_list_init(void)
{
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}


// add user page at the end of lru list
void add_page_to_lru_list(struct page *page)
{
	lock_acquire(&lru_list_lock);
	list_push_back(&lru_list, &page->lru);
	lock_release(&lru_list_lock);
}


//delete user page from lru list
void del_page_from_lru_list(struct page *page)
{
	lock_acquire(&lru_list_lock);
	list_remove(&page->lru);
	lock_release(&lru_list_lock);
}


// find page from lru list
struct page* find_page_from_lru_list(void* kaddr)
{
	lock_acquire(&lru_list_lock);
	struct list_elem *e;
  for (e = list_begin (&lru_list); e != list_end (&lru_list); e = list_next (e))
  {
    struct page *iter = list_entry(e, struct page, lru);
    if (iter->kaddr == kaddr)
    {
    	lock_release(&lru_list_lock);
      return iter;
    }
  }
  lock_release(&lru_list_lock);
  return NULL;
}

// get next lru_clock
// if lru list is not empty, this function infinitely gives next element
struct list_elem* get_next_lru_clock()
{
	lock_acquire(&lru_list_lock);
	struct list_elem* next;

	// if lru_list is empty, return NULL
	if (list_empty(&lru_list))
		next = NULL;

	// if lru_clock is NULL or last element of lru_list, return first element in lru_list
	else if (lru_clock == NULL || list_next(lru_clock) == list_end(&lru_list))
		next = list_begin(&lru_list);

	// otherwise, return next list element
	else
		next = list_next(lru_clock);

	lock_release(&lru_list_lock);
	return next;
}


// in case of full physical memory
void try_to_free_pages(void)
{
	lock_acquire(&lru_list_lock);
	struct page *page;
	struct thread *t;
	struct vm_entry *vme;

	struct list_elem* start = get_next_lru_clock();
	struct list_elem* e = start;

	if (start == NULL)
		return;

	while (1)
	{
		// target page
		page = list_entry(e, struct_page, lru);

		// thread and vme
		t = page->thread;
		vme = page->vme;


		// if pinned, pass
		if (page->vme->pinned)
			continue;
		
		// if accessed, pass
		if(pagedir_is_accessed(t->pagedir, vme->vaddr))
		{
			pagedir_set_accessed(t->pagedir, vme->vaddr, false);
			continue;
		}


		// Will be modified 3-2: implement case VM_BIN

		switch (vme->type)
		{
			case VM_BIN:
			{
				if(pagedir_is_dirty(t->pagedir, vme->vaddr))
				{
					vme->type = VM_ANON;
					vme->swap_slot = swap_out(page->kaddr);
				}
				break;
			}
			case VM_FILE:
			{
				break;
			}
			case VM_ANON:
			{
				vme->swap_slot = swap_out(page->kaddr);
				break;
			}
		}

		// modify data
		vme->is_loaded = false;

		// clear page
		pagedir_clear_page(t->pagedir, vme->vaddr);

		// free page
		_free_page(page);

		// if returns to the start or list is empty, exit
		// otherwise, proceed
		e = get_next_lru_clock();
		if (e == start || e == NULL)
			break;
	}
	lock_release(&lru_list_lock);
}


































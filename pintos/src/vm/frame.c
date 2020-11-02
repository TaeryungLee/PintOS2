#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
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
	//lock_acquire(&lru_list_lock);
	if (lru_clock == &page->lru)
		list_remove(lru_clock);
	list_remove(&page->lru);
	//lock_release(&lru_list_lock);
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


// allocate memory for page
struct page* alloc_page(enum palloc_flags flags)
{
	// allocate page structure
	struct page *page;
	page = calloc(1, sizeof(struct page));

	// allocate page memory
	page->kaddr = palloc_get_page(flags);

	// if memory full, try to free pages
	if (page->kaddr == NULL)
	{
		try_to_free_pages();
		page->kaddr = palloc_get_page(flags);
	}

	// if still full, return NULL
	if (page->kaddr == NULL)
		return NULL;

	page->thread = thread_current();

	// add page into lru list
	add_page_to_lru_list(page);
	return page;
}


void _free_page(struct page *page)
{
	palloc_free_page(page->kaddr);
	del_page_from_lru_list(page);
	free(page);
}


void free_page(void *kaddr)
{
	struct page *page = find_page_from_lru_list(kaddr);

	if (page == NULL)
	{
		printf("finding fucked\n");
		exits(-1, NULL);
	}

	_free_page(page);
}



// get next lru_clock
// if lru list is not empty, this function infinitely gives next element
struct list_elem* get_next_lru_clock(void)
{
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

	lru_clock = next;

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
	{
		lock_release(&lru_list_lock);
		return;
	}

	while (1)
	{
		// target page
		page = list_entry(e, struct page, lru);

		// thread and vme
		t = page->thread;
		vme = page->vme;


		// if pinned, pass
		if (page->vme->pinned)
		{
			printf("pinned\n");
			e = get_next_lru_clock();
			printf("list elem got %#x\n", e);
			if (e == start || e == NULL)
				break;
			continue;
		}
		
		// if accessed, pass
		if(pagedir_is_accessed(t->pagedir, vme->vaddr))
		{
			pagedir_set_accessed(t->pagedir, vme->vaddr, false);
			{
				printf("accessed\n");
				e = get_next_lru_clock();

				if (e == start || e == NULL)
					break;
				continue;
			}
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


































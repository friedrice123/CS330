#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include "mylib.h"

#define NEXT_POINTER(ptr) (*((void **)(ptr + 8)))
#define PREV_POINTER(ptr) (*((void **)(ptr + 16)))
#define SIZE_BLOCK(ptr)   (*(unsigned long *)(ptr))


void *free_mem_chunks_list = NULL;
unsigned long chunk_of_4MB = 4 * 1024 * 1024;

void merge_free_mem_chunks(void* ptr, unsigned long total_size){
	if(free_mem_chunks_list==NULL){
		free_mem_chunks_list = ptr;
		PREV_POINTER(ptr) = NULL;
		NEXT_POINTER(ptr) = NULL;
		SIZE_BLOCK(ptr) = total_size;
	}
	else{
		void *just_after = free_mem_chunks_list;
		PREV_POINTER(ptr) = NULL;
		NEXT_POINTER(ptr) = just_after;
		PREV_POINTER(just_after) = ptr;
		SIZE_BLOCK(ptr) = total_size;
		free_mem_chunks_list = ptr;
	}
}

void *memalloc(unsigned long size)
{
	printf("memalloc() called\n");
	unsigned long mem_requested = (size / 8) * 8 + (size % 8 != 0) * 8 + 8;
	if(mem_requested<24){
		mem_requested=24;
	}
	void *allocated_mem_ptr;
	if (free_mem_chunks_list == NULL)
	{
		unsigned long chunk_of_mmap = (mem_requested / chunk_of_4MB) * chunk_of_4MB;
		if(mem_requested % chunk_of_4MB != 0) chunk_of_mmap+=chunk_of_4MB;
		void *new_mem_ptr = mmap(NULL, chunk_of_mmap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		unsigned long b = chunk_of_mmap - mem_requested;
		if (b < 24)
		{
			// Just simply allocate memory in a new mmap chunk
			allocated_mem_ptr = new_mem_ptr;
			SIZE_BLOCK(allocated_mem_ptr) = chunk_of_mmap;
		}
		else
		{
			allocated_mem_ptr = new_mem_ptr;
			void *free_mem_ptr = allocated_mem_ptr + mem_requested;

			// Create a new free block to allocate required_space
			free_mem_chunks_list = free_mem_ptr;
			SIZE_BLOCK(free_mem_ptr) = b;
			NEXT_POINTER(free_mem_ptr) = NULL;
			PREV_POINTER(free_mem_ptr) = NULL;

			// Allocate the required space in the memory
			SIZE_BLOCK(allocated_mem_ptr) = mem_requested;
		}
	}
	else if (free_mem_chunks_list != NULL)
	{
		void *temp = free_mem_chunks_list;
		while (1)
		{
			unsigned long size_of_left = SIZE_BLOCK(temp);
			if (size_of_left >= mem_requested)
			{
				unsigned long b = size_of_left - mem_requested;
				if (b >= 24)
				{
					allocated_mem_ptr = temp;
					SIZE_BLOCK(allocated_mem_ptr) = mem_requested;
					void *free_mem_ptr = allocated_mem_ptr + mem_requested;

					// Delete the free chunk
					// Only 1 chunk in list
					if (NEXT_POINTER(temp) == NULL && PREV_POINTER(temp) == NULL) free_mem_chunks_list = NULL;

					// Delete from beginning
					else if (PREV_POINTER(temp) == NULL)
					{
						void *next_temp = NEXT_POINTER(temp);
						free_mem_chunks_list = next_temp;
						PREV_POINTER(next_temp) = NULL;
					}

					// Delete from middle
					else if (NEXT_POINTER(temp) != NULL && PREV_POINTER(temp) != NULL)
					{
						void *prev_temp = PREV_POINTER(temp);
						void *next_temp = NEXT_POINTER(temp);
						NEXT_POINTER(prev_temp) = next_temp;
						PREV_POINTER(next_temp) = prev_temp;
					}

					// Delete from end
					else if (NEXT_POINTER(temp) == NULL)
					{
						void *prev_temp = PREV_POINTER(temp);
						NEXT_POINTER(prev_temp) = NULL;
					}

					// Insertion of the free memory
					SIZE_BLOCK(free_mem_ptr) = b;
					if (free_mem_chunks_list != NULL)
					{
						void *just_after = free_mem_chunks_list;
						NEXT_POINTER(free_mem_ptr) = just_after;
						PREV_POINTER(free_mem_ptr) = NULL;
						PREV_POINTER(just_after) = free_mem_ptr;
						free_mem_chunks_list = free_mem_ptr;
					}
					else
					{
						free_mem_chunks_list = free_mem_ptr;
						SIZE_BLOCK(free_mem_ptr) = b;
						NEXT_POINTER(free_mem_ptr) = NULL;
						PREV_POINTER(free_mem_ptr) = NULL;
					}
				}
				else
				{
					allocated_mem_ptr = temp;
					SIZE_BLOCK(allocated_mem_ptr) = size_of_left;

					// Delete the free chunk
					// Only 1 chunk in list
					if (NEXT_POINTER(temp) == NULL && PREV_POINTER(temp) == NULL) free_mem_chunks_list = NULL;

					// Delete from beginning
					else if (PREV_POINTER(temp) == NULL)
					{
						void *next_temp = NEXT_POINTER(temp);
						free_mem_chunks_list = next_temp;
						PREV_POINTER(next_temp) = NULL;
					}

					// Delete from middle
					else if (NEXT_POINTER(temp) != NULL && PREV_POINTER(temp) != NULL)
					{
						void *prev_temp = PREV_POINTER(temp);
						void *next_temp = NEXT_POINTER(temp);
						NEXT_POINTER(prev_temp) = next_temp;
						PREV_POINTER(next_temp) = prev_temp;
					}

					// Delete from end
					else if (NEXT_POINTER(temp) == NULL)
					{
						void *prev_temp = PREV_POINTER(temp);
						NEXT_POINTER(prev_temp) = NULL;
					}
				}
				break;
			}
			else
			{
				temp = NEXT_POINTER(temp);
			}

			if (temp == NULL)
			{
				unsigned long chunk_of_mmap = (mem_requested / chunk_of_4MB) * chunk_of_4MB;
				if(mem_requested % chunk_of_4MB != 0) chunk_of_mmap += chunk_of_4MB;
				void *new_mem_ptr = mmap(NULL, chunk_of_mmap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
				unsigned long b = chunk_of_mmap - mem_requested;
				if (b >= 24)
				{
					allocated_mem_ptr = new_mem_ptr;
					SIZE_BLOCK(allocated_mem_ptr) = mem_requested;
					void *free_mem_ptr = allocated_mem_ptr + mem_requested;

					// Insert in the beginning
					SIZE_BLOCK(free_mem_ptr) = b;
					void *just_after = free_mem_chunks_list;
					NEXT_POINTER(free_mem_ptr) = just_after;
					PREV_POINTER(free_mem_ptr) = NULL;
					PREV_POINTER(just_after) = free_mem_ptr;
					free_mem_chunks_list = free_mem_ptr;
				}
				else
				{
					allocated_mem_ptr = new_mem_ptr;
					SIZE_BLOCK(allocated_mem_ptr) = chunk_of_mmap;
				}
				break;
			}
		}
	}
	return allocated_mem_ptr + 8;
}

int memfree(void *ptr)
{   
	printf("memfree() called\n");

	if(ptr==NULL) return -1;
	unsigned long size_of_right, size_of_left;

	// Step 1: Find out about the neighbours

	// If the right neighbour exists
	void *mid_start = ptr-8;
	unsigned long midsize = SIZE_BLOCK(mid_start);
	void *mid_end = mid_start + midsize;
	void *check_right=free_mem_chunks_list;
	int right_exists=0;
	while(check_right!=NULL){
		if(check_right==mid_end){
			right_exists=1;
			size_of_right=SIZE_BLOCK(mid_end);
			break;
		}
		check_right=NEXT_POINTER(check_right);
	}
	// If the left neighbour exists
	int left_exists=0;
	void *check_left=free_mem_chunks_list;
	check_left=free_mem_chunks_list;
	while(check_left!=NULL){
		unsigned long left_size = SIZE_BLOCK(check_left);
		if(check_left+left_size==mid_start){
			left_exists=1;
			size_of_left=left_size;
			break;
		}
		check_left=NEXT_POINTER(check_left);
	}
	// Step 2: Deleting the neighbours
	// Delete right neighbour if it exists
	if(right_exists){
		void *rstart = mid_end;
		// Only 1 chunk in list
		if (NEXT_POINTER(rstart) == NULL && PREV_POINTER(rstart) == NULL)
		{
			free_mem_chunks_list = NULL;
		}
		// Delete from end
		else if (NEXT_POINTER(rstart) == NULL)
		{
			void *prev_rstart = PREV_POINTER(rstart);
			NEXT_POINTER(prev_rstart) = NULL;
		}

		// Delete from beginning
		else if (PREV_POINTER(rstart) == NULL)
		{
			void *next_rstart = NEXT_POINTER(rstart);
			free_mem_chunks_list = next_rstart;
			PREV_POINTER(next_rstart) = NULL;
		}

		// Delete from middle
		else
		{
			void *prev_rstart = PREV_POINTER(rstart);
			void *next_rstart = NEXT_POINTER(rstart);
			NEXT_POINTER(prev_rstart) = next_rstart;
			PREV_POINTER(next_rstart) = prev_rstart;
		}
	} 

	// Delete left neighbour if it exists
	if(left_exists){
		void *lstart = mid_start - size_of_left;
		// Only 1 chunk in list
		if (NEXT_POINTER(lstart) == NULL && PREV_POINTER(lstart) == NULL)
		{
			free_mem_chunks_list = NULL;
		}
		// Delete from end
		else if (NEXT_POINTER(lstart) == NULL)
		{
			void *prev_lstart = PREV_POINTER(lstart);
			NEXT_POINTER(prev_lstart) = NULL;
		}

		// Delete from beginning
		else if (PREV_POINTER(lstart) == NULL)
		{
			void *next_lstart = NEXT_POINTER(lstart);
			free_mem_chunks_list = next_lstart;
			PREV_POINTER(next_lstart) = NULL;
		}

		// Delete from middle
		else
		{
			void *prev_lstart = PREV_POINTER(lstart);
			void *next_lstart = NEXT_POINTER(lstart);
			NEXT_POINTER(prev_lstart) = next_lstart;
			PREV_POINTER(next_lstart) = prev_lstart;
		}
	}

	// Step 3: Merging the blocks as per the existence of its neighbours
	if (right_exists && !left_exists){
		merge_free_mem_chunks(mid_start,midsize+size_of_right);
	}
	else if (!right_exists  && left_exists){
		merge_free_mem_chunks((mid_start-size_of_left),midsize+size_of_left);
	}
	else if (!right_exists && !left_exists){
		merge_free_mem_chunks(mid_start,midsize);
	}
	else{
		merge_free_mem_chunks((mid_start-size_of_left),midsize+size_of_right+size_of_left);
	}
	
	return 0;
}
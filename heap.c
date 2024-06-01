#include <stdlib.h>
#include "heap.h"

struct heap {
	int size;
	int limit;
	unsigned *allocs;
};
struct heap *heap_create() {
	struct heap *heap = (struct heap *)malloc(sizeof(*heap));
	heap->size = 256;
	heap->allocs = (unsigned *)malloc(heap->size * sizeof(unsigned));
	heap->limit = 0;
	return heap;
}
int heap_del(struct heap *heap, unsigned ptr) {
	for (int i = 0; i < heap->limit; i++)
		if (heap->allocs[i] == ptr) {
			if (i == heap->limit - 1)
				while (--heap->limit && !heap->allocs[heap->limit - 1])
					;
			else
				heap->allocs[i] = 0;
			return 1;
		}
	return 0;
}
int heap_add(struct heap *heap, unsigned ptr) {
	if (heap->limit < heap->size) {
		heap->allocs[heap->limit++] = ptr;
		return 1;
	}
	for (int i = 0; i < heap->size; i++)
		if (!heap->allocs[i]) {
			heap->allocs[i] = ptr;
			return 1;
		}
	int new_size = heap->size * 2;
	unsigned *new_allocs = (unsigned *)realloc(heap->allocs, new_size * sizeof(unsigned));
	if (!new_allocs)
		return 0;
	heap->size = new_size;
	heap->allocs = new_allocs;
	heap->allocs[heap->limit++] = ptr;
	return 1;
}
void heap_free_all(struct heap *heap) {
	for (int i = 0; i < heap->limit; i++)
		if (heap->allocs[i])
			free((void *)heap->allocs[i]);
	heap->limit = 0;
}
void heap_done(struct heap *heap) {
	free(heap->allocs);
	free(heap);
}

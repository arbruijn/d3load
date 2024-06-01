#ifndef HEAP_H
#define HEAP_H

struct heap *heap_create();
int heap_del(struct heap *heap, unsigned ptr);
int heap_add(struct heap *heap, unsigned ptr);
void heap_free_all(struct heap *heap);
void heap_done(struct heap *heap);

#endif

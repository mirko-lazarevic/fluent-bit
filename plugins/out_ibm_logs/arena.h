/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef FLB_OUT_IBM_CLOUD_LOGS_ARENA_H
#define FLB_OUT_IBM_CLOUD_LOGS_ARENA_H

#include <fluent-bit.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <string.h>

#define ARENA_ALIGNMENT 16

struct arena {
    char *start;
    char *current;
    size_t size;
    size_t used;
};

/* Align size to ARENA_ALIGNMENT boundary */
static inline size_t arena_align(size_t size) {
    return (size + ARENA_ALIGNMENT - 1) & ~(ARENA_ALIGNMENT - 1);
}

/* Initialize arena with pre-allocated memory */
static inline int arena_init(struct arena *arena, size_t size) {
    arena->start = (char *)flb_calloc(1, size);
    if (!arena->start) {
        return -1;
    }
    arena->current = arena->start;
    arena->size = size;
    arena->used = 0;
    return 0;
}

/* Allocate memory from arena */
static inline void *arena_alloc(struct arena *arena, size_t size) {
    if (!arena || !arena->start) {
        return NULL;
    }
    
    size_t aligned_size = arena_align(size);
    
    if (arena->used + aligned_size > arena->size) {
        return NULL; /* Arena full */
    }
    
    void *ptr = arena->current;
    arena->current += aligned_size;
    arena->used += aligned_size;
    
    return ptr;
}

/* Allocate zeroed memory from arena */
static inline void *arena_calloc(struct arena *arena, size_t count, size_t size) {
    size_t total = count * size;
    void *ptr = arena_alloc(arena, total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

/* Duplicate string in arena */
static inline char *arena_strdup(struct arena *arena, const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str) + 1;
    char *copy = (char *)arena_alloc(arena, len);
    if (copy) {
        memcpy(copy, str, len);
    }
    return copy;
}

/* Reset arena (keep memory allocated) */
static inline void arena_reset(struct arena *arena) {
    arena->current = arena->start;
    arena->used = 0;
    /* Optionally clear memory for security/debugging */
    /* memset(arena->start, 0, arena->size); */
}

/* Get arena usage statistics */
static inline void arena_stats(struct arena *arena, size_t *used, size_t *available) {
    if (used) *used = arena->used;
    if (available) *available = arena->size - arena->used;
}

/* Destroy arena and free memory */
static inline void arena_destroy(struct arena *arena) {
    if (arena->start) {
        flb_free(arena->start);
        arena->start = NULL;
        arena->current = NULL;
        arena->size = 0;
        arena->used = 0;
    }
}

/* Check if arena can accommodate size */
static inline int arena_can_alloc(struct arena *arena, size_t size) {
    return (arena->used + arena_align(size) <= arena->size);
}

#endif
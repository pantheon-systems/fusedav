#ifndef foostatcachehfoo
#define foostatcachehfoo

#include <sys/stat.h>

int stat_cache_get(const char *fn, struct stat *st);
void stat_cache_set(const char *fn, const struct stat *st);
void stat_cache_invalidate(const char*fn);

void dir_cache_invalidate(const char*fn);
void dir_cache_invalidate_parent(const char *fn);
void dir_cache_begin(const char *fn);
void dir_cache_finish(const char *fn, int success);
void dir_cache_add(const char *fn, const char *subdir, int is_dir);
int dir_cache_enumerate(const char *fn, void (*f) (const char*fn, const char *subdir, int is_dir, void *user), void *user);

void cache_free(void);
void cache_alloc(void);

#endif

#ifndef foofilecachehfoo
#define foofilecachehfoo

#include <sys/types.h>

void* file_cache_open(const char *path, int flags);
void* file_cache_get(const char *path);
void file_cache_unref(void *f);

int file_cache_close(void *f);

int file_cache_read(void *f, char *buf, size_t size, off_t offset);
int file_cache_write(void *f, const char *buf, size_t size, off_t offset);
int file_cache_truncate(void *f, off_t s);
int file_cache_sync(void *f);
int file_cache_close_all(void);


#endif

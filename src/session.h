#ifndef foosessionhfoo
#define foosessionhfoo

#include <ne_session.h>

ne_session *session_get(void);
int session_set_uri(const char *s, const char*u, const char*p);
void session_free(void);

extern const char *base_directory;

#endif

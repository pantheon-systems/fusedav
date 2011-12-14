#ifndef foosessionhfoo
#define foosessionhfoo

/* $Id$ */

/***
  This file is part of fusedav.

  fusedav is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  fusedav is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.
  
  You should have received a copy of the GNU General Public License
  along with fusedav; if not, write to the Free Software Foundation,
  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
***/

#include <ne_session.h>
#include <ne_locks.h>

ne_session *session_get(int with_lock);
int session_set_uri(const char *s, const char*u, const char*p, const char *client_cert, const char *ca_cert);
void session_free(void);

int session_is_local(const ne_uri *u);

extern char *base_directory;
extern ne_uri uri;
extern char *username;

#endif

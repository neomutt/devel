/*
 * Copyright (C) 2009,2013,2016 Derek Martin <code@pizzashack.org>
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "mutt.h"


int getdnsdomainname (char *d, size_t len)
{
  int ret = -1;

#if defined HAVE_GETADDRINFO || defined HAVE_GETADDRINFO_A
  char node[STRING];
  if (gethostname(node, sizeof(node)))
    return ret;

  struct addrinfo hints;
  struct addrinfo *h = NULL;

  *d = '\0';
  memset(&hints, 0, sizeof (struct addrinfo));
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = AF_UNSPEC;

#ifdef HAVE_GETADDRINFO_A

  /* Allow 0.1 seconds to get the FQDN (fully-qualified domain name).
   * If it takes longer, the system is mis-configured and the network is not
   * working properly, so...
   */
  struct timespec timeout = {0, 100000000};
  struct gaicb *reqs[1];
  reqs[0] = safe_calloc(1, sizeof(*reqs[0]));
  reqs[0]->ar_name = node;
  reqs[0]->ar_request = &hints;
  if ((getaddrinfo_a(GAI_NOWAIT, reqs, 1, NULL) == 0) &&
      (gai_suspend((const struct gaicb * const *) reqs, 1, &timeout) == 0) &&
      (gai_error(reqs[0]) == 0))
  {
    h = reqs[0]->ar_result;
  }
  FREE(&reqs[0]);

#else /* !HAVE_GETADDRINFO_A */

  getaddrinfo(node, NULL, &hints, &h)

#endif

  char *p;
  if (h != NULL && h->ai_canonname && (p = strchr(h->ai_canonname, '.')))
  {
    strfcpy(d, ++p, len);
    ret = 0;
    mutt_debug (1, "getdnsdomainname(): %s\n", d);
    freeaddrinfo(h);
  }

#endif /* HAVE_GETADDRINFO || defined HAVE_GETADDRINFO_A */

  return ret;
}


/**
 * @file
 * RFC822 Email format routines
 *
 * @authors
 * Copyright (C) 1996-2000,2011-2013 Michael R. Elkins <me@mutt.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include "lib/lib.h"
#include "rfc822.h"
#include "mutt_idna.h"

const char RFC822Specials[] = "@.,:;<>[]\\\"()";
#define is_special(x) strchr(RFC822Specials, x)

int RFC822Error = 0;

/* these must defined in the same order as the numerated errors given in rfc822.h */
const char *const RFC822Errors[] = {
  "out of memory",   "mismatched parenthesis", "mismatched quotes",
  "bad route in <>", "bad address in <>",      "bad address spec",
};

static void free_address(struct Address *a)
{
  FREE(&a->personal);
  FREE(&a->mailbox);
  FREE(&a);
}

int rfc822_remove_from_adrlist(struct Address **a, const char *mailbox)
{
  struct Address *p = NULL, *last = NULL, *t = NULL;
  int rv = -1;

  p = *a;
  last = NULL;
  while (p)
  {
    if (mutt_strcasecmp(mailbox, p->mailbox) == 0)
    {
      if (last)
        last->next = p->next;
      else
        (*a) = p->next;
      t = p;
      p = p->next;
      free_address(t);
      rv = 0;
    }
    else
    {
      last = p;
      p = p->next;
    }
  }

  return rv;
}

void rfc822_free_address(struct Address **p)
{
  struct Address *t = NULL;

  while (*p)
  {
    t = *p;
    *p = (*p)->next;
    FREE(&t->personal);
    FREE(&t->mailbox);
    FREE(&t);
  }
}

static const char *parse_comment(const char *s, char *comment, size_t *commentlen, size_t commentmax)
{
  int level = 1;

  while (*s && level)
  {
    if (*s == '(')
      level++;
    else if (*s == ')')
    {
      if (--level == 0)
      {
        s++;
        break;
      }
    }
    else if (*s == '\\')
    {
      if (!*++s)
        break;
    }
    if (*commentlen < commentmax)
      comment[(*commentlen)++] = *s;
    s++;
  }
  if (level)
  {
    RFC822Error = ERR_MISMATCH_PAREN;
    return NULL;
  }
  return s;
}

static const char *parse_quote(const char *s, char *token, size_t *tokenlen, size_t tokenmax)
{
  while (*s)
  {
    if (*tokenlen < tokenmax)
      token[*tokenlen] = *s;
    if (*s == '\\')
    {
      if (!*++s)
        break;

      if (*tokenlen < tokenmax)
        token[*tokenlen] = *s;
    }
    else if (*s == '"')
      return (s + 1);
    (*tokenlen)++;
    s++;
  }
  RFC822Error = ERR_MISMATCH_QUOTE;
  return NULL;
}

static const char *next_token(const char *s, char *token, size_t *tokenlen, size_t tokenmax)
{
  if (*s == '(')
    return (parse_comment(s + 1, token, tokenlen, tokenmax));
  if (*s == '"')
    return (parse_quote(s + 1, token, tokenlen, tokenmax));
  if (*s && is_special(*s))
  {
    if (*tokenlen < tokenmax)
      token[(*tokenlen)++] = *s;
    return (s + 1);
  }
  while (*s)
  {
    if (is_email_wsp(*s) || is_special(*s))
      break;
    if (*tokenlen < tokenmax)
      token[(*tokenlen)++] = *s;
    s++;
  }
  return s;
}

static const char *parse_mailboxdomain(const char *s, const char *nonspecial,
                                       char *mailbox, size_t *mailboxlen,
                                       size_t mailboxmax, char *comment,
                                       size_t *commentlen, size_t commentmax)
{
  const char *ps = NULL;

  while (*s)
  {
    s = skip_email_wsp(s);
    if (!*s)
      return s;

    if (strchr(nonspecial, *s) == NULL && is_special(*s))
      return s;

    if (*s == '(')
    {
      if (*commentlen && *commentlen < commentmax)
        comment[(*commentlen)++] = ' ';
      ps = next_token(s, comment, commentlen, commentmax);
    }
    else
      ps = next_token(s, mailbox, mailboxlen, mailboxmax);
    if (!ps)
      return NULL;
    s = ps;
  }

  return s;
}

static const char *parse_address(const char *s, char *token, size_t *tokenlen,
                                 size_t tokenmax, char *comment, size_t *commentlen,
                                 size_t commentmax, struct Address *addr)
{
  s = parse_mailboxdomain(s, ".\"(\\", token, tokenlen, tokenmax, comment,
                          commentlen, commentmax);
  if (!s)
    return NULL;

  if (*s == '@')
  {
    if (*tokenlen < tokenmax)
      token[(*tokenlen)++] = '@';
    s = parse_mailboxdomain(s + 1, ".([]\\", token, tokenlen, tokenmax, comment,
                            commentlen, commentmax);
    if (!s)
      return NULL;
  }

  terminate_string(token, *tokenlen, tokenmax);
  addr->mailbox = safe_strdup(token);

  if (*commentlen && !addr->personal)
  {
    terminate_string(comment, *commentlen, commentmax);
    addr->personal = safe_strdup(comment);
  }

  return s;
}

static const char *parse_route_addr(const char *s, char *comment, size_t *commentlen,
                                    size_t commentmax, struct Address *addr)
{
  char token[LONG_STRING];
  size_t tokenlen = 0;

  s = skip_email_wsp(s);

  /* find the end of the route */
  if (*s == '@')
  {
    while (s && *s == '@')
    {
      if (tokenlen < sizeof(token) - 1)
        token[tokenlen++] = '@';
      s = parse_mailboxdomain(s + 1, ",.\\[](", token, &tokenlen,
                              sizeof(token) - 1, comment, commentlen, commentmax);
    }
    if (!s || *s != ':')
    {
      RFC822Error = ERR_BAD_ROUTE;
      return NULL; /* invalid route */
    }

    if (tokenlen < sizeof(token) - 1)
      token[tokenlen++] = ':';
    s++;
  }

  if ((s = parse_address(s, token, &tokenlen, sizeof(token) - 1, comment,
                         commentlen, commentmax, addr)) == NULL)
    return NULL;

  if (*s != '>')
  {
    RFC822Error = ERR_BAD_ROUTE_ADDR;
    return NULL;
  }

  if (!addr->mailbox)
    addr->mailbox = safe_strdup("@");

  s++;
  return s;
}

static const char *parse_addr_spec(const char *s, char *comment, size_t *commentlen,
                                   size_t commentmax, struct Address *addr)
{
  char token[LONG_STRING];
  size_t tokenlen = 0;

  s = parse_address(s, token, &tokenlen, sizeof(token) - 1, comment, commentlen,
                    commentmax, addr);
  if (s && *s && *s != ',' && *s != ';')
  {
    RFC822Error = ERR_BAD_ADDR_SPEC;
    return NULL;
  }
  return s;
}

static void add_addrspec(struct Address **top, struct Address **last, const char *phrase,
                         char *comment, size_t *commentlen, size_t commentmax)
{
  struct Address *cur = rfc822_new_address();

  if (parse_addr_spec(phrase, comment, commentlen, commentmax, cur) == NULL)
  {
    rfc822_free_address(&cur);
    return;
  }

  if (*last)
    (*last)->next = cur;
  else
    *top = cur;
  *last = cur;
}

struct Address *rfc822_parse_adrlist(struct Address *top, const char *s)
{
  int ws_pending, nl;
  const char *ps = NULL;
  char comment[LONG_STRING], phrase[LONG_STRING];
  size_t phraselen = 0, commentlen = 0;
  struct Address *cur = NULL, *last = NULL;

  RFC822Error = 0;

  last = top;
  while (last && last->next)
    last = last->next;

  ws_pending = is_email_wsp(*s);
  if ((nl = mutt_strlen(s)))
    nl = s[nl - 1] == '\n';

  s = skip_email_wsp(s);
  while (*s)
  {
    if (*s == ',')
    {
      if (phraselen)
      {
        terminate_buffer(phrase, phraselen);
        add_addrspec(&top, &last, phrase, comment, &commentlen, sizeof(comment) - 1);
      }
      else if (commentlen && last && !last->personal)
      {
        terminate_buffer(comment, commentlen);
        last->personal = safe_strdup(comment);
      }

      commentlen = 0;
      phraselen = 0;
      s++;
    }
    else if (*s == '(')
    {
      if (commentlen && commentlen < sizeof(comment) - 1)
        comment[commentlen++] = ' ';
      ps = next_token(s, comment, &commentlen, sizeof(comment) - 1);
      if (!ps)
      {
        rfc822_free_address(&top);
        return NULL;
      }
      s = ps;
    }
    else if (*s == '"')
    {
      if (phraselen && phraselen < sizeof(phrase) - 1)
        phrase[phraselen++] = ' ';
      ps = parse_quote(s + 1, phrase, &phraselen, sizeof(phrase) - 1);
      if (!ps)
      {
        rfc822_free_address(&top);
        return NULL;
      }
      s = ps;
    }
    else if (*s == ':')
    {
      cur = rfc822_new_address();
      terminate_buffer(phrase, phraselen);
      cur->mailbox = safe_strdup(phrase);
      cur->group = 1;

      if (last)
        last->next = cur;
      else
        top = cur;
      last = cur;

      phraselen = 0;
      commentlen = 0;
      s++;
    }
    else if (*s == ';')
    {
      if (phraselen)
      {
        terminate_buffer(phrase, phraselen);
        add_addrspec(&top, &last, phrase, comment, &commentlen, sizeof(comment) - 1);
      }
      else if (commentlen && last && !last->personal)
      {
        terminate_buffer(comment, commentlen);
        last->personal = safe_strdup(comment);
      }

      /* add group terminator */
      cur = rfc822_new_address();
      if (last)
      {
        last->next = cur;
        last = cur;
      }

      phraselen = 0;
      commentlen = 0;
      s++;
    }
    else if (*s == '<')
    {
      terminate_buffer(phrase, phraselen);
      cur = rfc822_new_address();
      if (phraselen)
        cur->personal = safe_strdup(phrase);
      ps = parse_route_addr(s + 1, comment, &commentlen, sizeof(comment) - 1, cur);
      if (!ps)
      {
        rfc822_free_address(&top);
        rfc822_free_address(&cur);
        return NULL;
      }

      if (last)
        last->next = cur;
      else
        top = cur;
      last = cur;

      phraselen = 0;
      commentlen = 0;
      s = ps;
    }
    else
    {
      if (phraselen && phraselen < sizeof(phrase) - 1 && ws_pending)
        phrase[phraselen++] = ' ';
      ps = next_token(s, phrase, &phraselen, sizeof(phrase) - 1);
      if (!ps)
      {
        rfc822_free_address(&top);
        return NULL;
      }
      s = ps;
    }
    ws_pending = is_email_wsp(*s);
    s = skip_email_wsp(s);
  }

  if (phraselen)
  {
    terminate_buffer(phrase, phraselen);
    terminate_buffer(comment, commentlen);
    add_addrspec(&top, &last, phrase, comment, &commentlen, sizeof(comment) - 1);
  }
  else if (commentlen && last && !last->personal)
  {
    terminate_buffer(comment, commentlen);
    last->personal = safe_strdup(comment);
  }

  return top;
}

void rfc822_qualify(struct Address *addr, const char *host)
{
  char *p = NULL;

  for (; addr; addr = addr->next)
    if (!addr->group && addr->mailbox && strchr(addr->mailbox, '@') == NULL)
    {
      p = safe_malloc(mutt_strlen(addr->mailbox) + mutt_strlen(host) + 2);
      sprintf(p, "%s@%s", addr->mailbox, host);
      FREE(&addr->mailbox);
      addr->mailbox = p;
    }
}

void rfc822_cat(char *buf, size_t buflen, const char *value, const char *specials)
{
  if (strpbrk(value, specials))
  {
    char tmp[256], *pc = tmp;
    size_t tmplen = sizeof(tmp) - 3;

    *pc++ = '"';
    for (; *value && tmplen > 1; value++)
    {
      if (*value == '\\' || *value == '"')
      {
        *pc++ = '\\';
        tmplen--;
      }
      *pc++ = *value;
      tmplen--;
    }
    *pc++ = '"';
    *pc = 0;
    strfcpy(buf, tmp, buflen);
  }
  else
    strfcpy(buf, value, buflen);
}

void rfc822_write_address_single(char *buf, size_t buflen, struct Address *addr, int display)
{
  size_t len;
  char *pbuf = buf;
  char *pc = NULL;

  if (!addr)
    return;

  buflen--; /* save room for the terminal nul */

  if (addr->personal)
  {
    if (strpbrk(addr->personal, RFC822Specials))
    {
      if (!buflen)
        goto done;
      *pbuf++ = '"';
      buflen--;
      for (pc = addr->personal; *pc && buflen > 0; pc++)
      {
        if (*pc == '"' || *pc == '\\')
        {
          *pbuf++ = '\\';
          buflen--;
        }
        if (!buflen)
          goto done;
        *pbuf++ = *pc;
        buflen--;
      }
      if (!buflen)
        goto done;
      *pbuf++ = '"';
      buflen--;
    }
    else
    {
      if (!buflen)
        goto done;
      strfcpy(pbuf, addr->personal, buflen);
      len = mutt_strlen(pbuf);
      pbuf += len;
      buflen -= len;
    }

    if (!buflen)
      goto done;
    *pbuf++ = ' ';
    buflen--;
  }

  if (addr->personal || (addr->mailbox && *addr->mailbox == '@'))
  {
    if (!buflen)
      goto done;
    *pbuf++ = '<';
    buflen--;
  }

  if (addr->mailbox)
  {
    if (!buflen)
      goto done;
    if ((mutt_strcmp(addr->mailbox, "@") != 0) && !display)
    {
      strfcpy(pbuf, addr->mailbox, buflen);
      len = mutt_strlen(pbuf);
    }
    else if ((mutt_strcmp(addr->mailbox, "@") != 0) && display)
    {
      strfcpy(pbuf, mutt_addr_for_display(addr), buflen);
      len = mutt_strlen(pbuf);
    }
    else
    {
      *pbuf = '\0';
      len = 0;
    }
    pbuf += len;
    buflen -= len;

    if (addr->personal || (addr->mailbox && *addr->mailbox == '@'))
    {
      if (!buflen)
        goto done;
      *pbuf++ = '>';
      buflen--;
    }

    if (addr->group)
    {
      if (!buflen)
        goto done;
      *pbuf++ = ':';
      buflen--;
      if (!buflen)
        goto done;
      *pbuf++ = ' ';
      buflen--;
    }
  }
  else
  {
    if (!buflen)
      goto done;
    *pbuf++ = ';';
    buflen--;
  }
done:
  /* no need to check for length here since we already save space at the
     beginning of this routine */
  *pbuf = 0;
}

/**
 * rfc822_write_address - Write an address to a buffer
 *
 * Note: it is assumed that `buf' is nul terminated!
 */
int rfc822_write_address(char *buf, size_t buflen, struct Address *addr, int display)
{
  char *pbuf = buf;
  size_t len = mutt_strlen(buf);

  buflen--; /* save room for the terminal nul */

  if (len > 0)
  {
    if (len > buflen)
      return pbuf - buf; /* safety check for bogus arguments */

    pbuf += len;
    buflen -= len;
    if (!buflen)
      goto done;
    *pbuf++ = ',';
    buflen--;
    if (!buflen)
      goto done;
    *pbuf++ = ' ';
    buflen--;
  }

  for (; addr && buflen > 0; addr = addr->next)
  {
    /* use buflen+1 here because we already saved space for the trailing
       nul char, and the subroutine can make use of it */
    rfc822_write_address_single(pbuf, buflen + 1, addr, display);

    /* this should be safe since we always have at least 1 char passed into
       the above call, which means `pbuf' should always be nul terminated */
    len = mutt_strlen(pbuf);
    pbuf += len;
    buflen -= len;

    /* if there is another address, and it's not a group mailbox name or
       group terminator, add a comma to separate the addresses */
    if (addr->next && addr->next->mailbox && !addr->group)
    {
      if (!buflen)
        goto done;
      *pbuf++ = ',';
      buflen--;
      if (!buflen)
        goto done;
      *pbuf++ = ' ';
      buflen--;
    }
  }
done:
  *pbuf = 0;
  return pbuf - buf;
}

/**
 * rfc822_cpy_adr_real - Copy the real address
 *
 * this should be rfc822_cpy_adr
 */
struct Address *rfc822_cpy_adr_real(struct Address *addr)
{
  struct Address *p = rfc822_new_address();

  p->personal = safe_strdup(addr->personal);
  p->mailbox = safe_strdup(addr->mailbox);
  p->group = addr->group;
  p->is_intl = addr->is_intl;
  p->intl_checked = addr->intl_checked;
  return p;
}

/**
 * rfc822_cpy_adr - Copy a list of addresses
 *
 * this should be rfc822_cpy_adrlist
 */
struct Address *rfc822_cpy_adr(struct Address *addr, int prune)
{
  struct Address *top = NULL, *last = NULL;

  for (; addr; addr = addr->next)
  {
    if (prune && addr->group && (!addr->next || !addr->next->mailbox))
    {
      /* ignore this element of the list */
    }
    else if (last)
    {
      last->next = rfc822_cpy_adr_real(addr);
      last = last->next;
    }
    else
      top = last = rfc822_cpy_adr_real(addr);
  }
  return top;
}

/**
 * rfc822_append - Append one list of addresses on another
 *
 * append list 'b' to list 'a' and return the last element in the new list
 */
struct Address *rfc822_append(struct Address **a, struct Address *b, int prune)
{
  struct Address *tmp = *a;

  while (tmp && tmp->next)
    tmp = tmp->next;
  if (!b)
    return tmp;
  if (tmp)
    tmp->next = rfc822_cpy_adr(b, prune);
  else
    tmp = *a = rfc822_cpy_adr(b, prune);
  while (tmp && tmp->next)
    tmp = tmp->next;
  return tmp;
}

/**
 * rfc822_valid_msgid - Is the message id valid
 *
 * incomplete. Only used to thwart the APOP MD5 attack (#2846).
 */
bool rfc822_valid_msgid(const char *msgid)
{
  /* msg-id         = "<" addr-spec ">"
   * addr-spec      = local-part "@" domain
   * local-part     = word *("." word)
   * word           = atom / quoted-string
   * atom           = 1*<any CHAR except specials, SPACE and CTLs>
   * CHAR           = ( 0.-127. )
   * specials       = "(" / ")" / "<" / ">" / "@"
                    / "," / ";" / ":" / "\" / <">
                    / "." / "[" / "]"
   * SPACE          = ( 32. )
   * CTLS           = ( 0.-31., 127.)
   * quoted-string  = <"> *(qtext/quoted-pair) <">
   * qtext          = <any CHAR except <">, "\" and CR>
   * CR             = ( 13. )
   * quoted-pair    = "\" CHAR
   * domain         = sub-domain *("." sub-domain)
   * sub-domain     = domain-ref / domain-literal
   * domain-ref     = atom
   * domain-literal = "[" *(dtext / quoted-pair) "]"
   */

  unsigned int l;

  if (!msgid || !*msgid)
    return false;

  l = mutt_strlen(msgid);
  if (l < 5) /* <atom@atom> */
    return false;
  if (msgid[0] != '<' || msgid[l - 1] != '>')
    return false;
  if (!(strrchr(msgid, '@')))
    return false;

  /* TODO: complete parser */
  for (unsigned int i = 0; i < l; i++)
    if ((unsigned char) msgid[i] > 127)
      return false;

  return true;
}

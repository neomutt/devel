/**
 * @file
 * Representation of the body of an email
 *
 * @authors
 * Copyright (C) 2017 Richard Russon <rich@flatcap.org>
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
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include "mutt/debug.h"
#include "mutt/memory.h"
#include "mutt/string2.h"
#include "body.h"
#include "header.h"
#include "mime.h"
#include "parameter.h"
#include "protos.h"

struct Body *mutt_new_body(void)
{
  struct Body *p = mutt_mem_calloc(1, sizeof(struct Body));

  p->disposition = DISPATTACH;
  p->use_disp = true;
  return p;
}

/**
 * mutt_copy_body - create a send-mode duplicate from a receive-mode body
 */
int mutt_copy_body(FILE *fp, struct Body **tgt, struct Body *src)
{
  if (!tgt || !src)
    return -1;

  char tmp[_POSIX_PATH_MAX];
  struct Body *b = NULL;

  struct Parameter *par = NULL, **ppar = NULL;

  bool use_disp;

  if (src->filename)
  {
    use_disp = true;
    mutt_str_strfcpy(tmp, src->filename, sizeof(tmp));
  }
  else
  {
    use_disp = false;
    tmp[0] = '\0';
  }

  mutt_adv_mktemp(tmp, sizeof(tmp));
  if (mutt_save_attachment(fp, src, tmp, 0, NULL) == -1)
    return -1;

  *tgt = mutt_new_body();
  b = *tgt;

  memcpy(b, src, sizeof(struct Body));
  b->parts = NULL;
  b->next = NULL;

  b->filename = mutt_str_strdup(tmp);
  b->use_disp = use_disp;
  b->unlink = true;

  if (mutt_is_text_part(b))
    b->noconv = true;

  b->xtype = mutt_str_strdup(b->xtype);
  b->subtype = mutt_str_strdup(b->subtype);
  b->form_name = mutt_str_strdup(b->form_name);
  b->d_filename = mutt_str_strdup(b->d_filename);
  /* mutt_adv_mktemp() will mangle the filename in tmp,
   * so preserve it in d_filename */
  if (!b->d_filename && use_disp)
    b->d_filename = mutt_str_strdup(src->filename);
  b->description = mutt_str_strdup(b->description);

  /*
   * we don't seem to need the Header structure currently.
   * XXX - this may change in the future
   */

  if (b->hdr)
    b->hdr = NULL;

  /* copy parameters */
  for (par = b->parameter, ppar = &b->parameter; par; ppar = &(*ppar)->next, par = par->next)
  {
    *ppar = mutt_param_new();
    (*ppar)->attribute = mutt_str_strdup(par->attribute);
    (*ppar)->value = mutt_str_strdup(par->value);
  }

  mutt_stamp_attachment(b);

  return 0;
}

void mutt_free_body(struct Body **p)
{
  struct Body *a = *p, *b = NULL;

  while (a)
  {
    b = a;
    a = a->next;

    if (b->parameter)
      mutt_param_free(&b->parameter);
    if (b->filename)
    {
      if (b->unlink)
        unlink(b->filename);
      mutt_debug(1, "%sunlinking %s.\n", b->unlink ? "" : "not ", b->filename);
    }

    FREE(&b->filename);
    FREE(&b->d_filename);
    FREE(&b->charset);
    FREE(&b->content);
    FREE(&b->xtype);
    FREE(&b->subtype);
    FREE(&b->description);
    FREE(&b->form_name);

    if (b->hdr)
    {
      /* Don't free twice (b->hdr->content = b->parts) */
      b->hdr->content = NULL;
      mutt_free_header(&b->hdr);
    }

    if (b->parts)
      mutt_free_body(&b->parts);

    FREE(&b);
  }

  *p = 0;
}

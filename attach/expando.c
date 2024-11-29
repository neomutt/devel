/**
 * @file
 * Attach Expando definitions
 *
 * @authors
 * Copyright (C) 2024 Richard Russon <rich@flatcap.org>
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

/**
 * @page attach_expando Attach Expando definitions
 *
 * Attach Expando definitions
 */

#include <stdbool.h>
#include <stdio.h>
#include "mutt/lib.h"
#include "email/lib.h"
#include "core/lib.h"
#include "expando.h"
#include "lib.h"
#include "color/lib.h"
#include "expando/lib.h"
#include "index/lib.h"
#include "attach.h"
#include "muttlib.h"

static void body_file_disposition(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf);

/**
 * attach_charset - Attachment: Charset - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void attach_charset(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  char tmp[128] = { 0 };

  if (mutt_is_text_part(aptr->body) && mutt_body_get_charset(aptr->body, tmp, sizeof(tmp)))
  {
    buf_strcpy(buf, tmp);
  }
}

/**
 * attach_number_num - Attachment: Index number - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long attach_number_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;

  return aptr->num + 1;
}

/**
 * attach_tree - Attachment: Tree characters - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void attach_tree(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  node_expando_set_color(node, MT_COLOR_TREE);
  node_expando_set_has_tree(node, true);
  const char *s = aptr->tree;
  buf_strcpy(buf, s);
}

/**
 * body_attach_count_num - Body: Number of MIME parts - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long body_attach_count_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;
  const struct Body *body = aptr->body;

  return body->attach_count + body->attach_qualifies;
}

/**
 * body_attach_qualifies - Body: Attachment counting - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_attach_qualifies(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = aptr->body->attach_qualifies ? "Q" : " ";
  buf_strcpy(buf, s);
}

/**
 * body_attach_qualifies_num - Body: Attachment counting - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long body_attach_qualifies_num(const struct ExpandoNode *node,
                                      void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;
  return aptr->body->attach_qualifies;
}

/**
 * body_charset_convert - Body: Requires conversion flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_charset_convert(const struct ExpandoNode *node, void *data,
                                 MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = ((aptr->body->type != TYPE_TEXT) || aptr->body->noconv) ? "n" : "c";
  buf_strcpy(buf, s);
}

/**
 * body_deleted - Body: Deleted - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_deleted(const struct ExpandoNode *node, void *data,
                         MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = aptr->body->deleted ? "D" : " ";
  buf_strcpy(buf, s);
}

/**
 * body_deleted_num - Body: Deleted - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long body_deleted_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;
  return aptr->body->deleted;
}

/**
 * body_description - Body: Description - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_description(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  const struct Expando *c_message_format = cs_subset_expando(NeoMutt->sub, "message_format");
  if (aptr->body->description)
  {
    const char *s = aptr->body->description;
    buf_strcpy(buf, s);
    return;
  }

  if (mutt_is_message_type(aptr->body->type, aptr->body->subtype) &&
      c_message_format && aptr->body->email)
  {
    mutt_make_string(buf, -1, c_message_format, NULL, -1, aptr->body->email,
                     MUTT_FORMAT_FORCESUBJ | MUTT_FORMAT_ARROWCURSOR, NULL);

    return;
  }

  if (!aptr->body->d_filename && !aptr->body->filename)
  {
    const char *s = "<no description>";
    buf_strcpy(buf, s);
    return;
  }

  body_file_disposition(node, data, flags, buf);
}

/**
 * body_disposition - Body: Disposition flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_disposition(const struct ExpandoNode *node, void *data,
                             MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  // NOTE(g0mb4): use $to_chars?
  static const char dispchar[] = { 'I', 'A', 'F', '-' };
  char ch;

  if (aptr->body->disposition < sizeof(dispchar))
  {
    ch = dispchar[aptr->body->disposition];
  }
  else
  {
    mutt_debug(LL_DEBUG1, "ERROR: invalid content-disposition %d\n", aptr->body->disposition);
    ch = '!';
  }

  buf_printf(buf, "%c", ch);
}

/**
 * body_file - Body: Filename - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_file(const struct ExpandoNode *node, void *data,
                      MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  if (aptr->body->filename && (*aptr->body->filename == '/'))
  {
    struct Buffer *path = buf_pool_get();

    buf_strcpy(path, aptr->body->filename);
    buf_pretty_mailbox(path);
    buf_copy(buf, path);
    buf_pool_release(&path);
  }
  else
  {
    const char *s = aptr->body->filename;
    buf_strcpy(buf, s);
  }
}

/**
 * body_file_disposition - Body: Filename in header - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_file_disposition(const struct ExpandoNode *node, void *data,
                                  MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  if (aptr->body->d_filename)
  {
    const char *s = aptr->body->d_filename;
    buf_strcpy(buf, s);
    return;
  }

  body_file(node, data, flags, buf);
}

/**
 * body_file_size - Body: Size - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_file_size(const struct ExpandoNode *node, void *data,
                           MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  size_t l = 0;
  if (aptr->body->filename && (flags & MUTT_FORMAT_STAT_FILE))
  {
    l = mutt_file_get_size(aptr->body->filename);
  }
  else
  {
    l = aptr->body->length;
  }

  mutt_str_pretty_size(buf, l);
}

/**
 * body_file_size_num - Body: Size - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long body_file_size_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;

  if (aptr->body->filename && (flags & MUTT_FORMAT_STAT_FILE))
    return mutt_file_get_size(aptr->body->filename);

  return aptr->body->length;
}

/**
 * body_mime_encoding - Body: MIME type - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_mime_encoding(const struct ExpandoNode *node, void *data,
                               MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  const char *s = ENCODING(aptr->body->encoding);
  buf_strcpy(buf, s);
}

/**
 * body_mime_major - Body: Major MIME type - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_mime_major(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  const char *s = BODY_TYPE(aptr->body);
  buf_strcpy(buf, s);
}

/**
 * body_mime_minor - Body: MIME subtype - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_mime_minor(const struct ExpandoNode *node, void *data,
                            MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  const char *s = aptr->body->subtype;
  buf_strcpy(buf, s);
}

/**
 * body_tagged - Body: Is Tagged - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_tagged(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = aptr->body->tagged ? "*" : " ";
  buf_strcpy(buf, s);
}

/**
 * body_tagged_num - Body: Is Tagged - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long body_tagged_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;
  return aptr->body->tagged;
}

/**
 * body_unlink - Body: Unlink flag - Implements ::get_string_t - @ingroup expando_get_string_api
 */
static void body_unlink(const struct ExpandoNode *node, void *data,
                        MuttFormatFlags flags, struct Buffer *buf)
{
  const struct AttachPtr *aptr = data;

  // NOTE(g0mb4): use $to_chars?
  const char *s = aptr->body->unlink ? "-" : " ";
  buf_strcpy(buf, s);
}

/**
 * body_unlink_num - Body: Unlink flag - Implements ::get_number_t - @ingroup expando_get_number_api
 */
static long body_unlink_num(const struct ExpandoNode *node, void *data, MuttFormatFlags flags)
{
  const struct AttachPtr *aptr = data;
  return aptr->body->unlink;
}

/**
 * AttachRenderCallbacks1 - Callbacks for Attachment Expandos
 *
 * @sa AttachFormatDef, ExpandoDataAttach, ExpandoDataBody, ExpandoDataGlobal
 */
const struct ExpandoRenderCallback AttachRenderCallbacks1[] = {
  // clang-format off
  { ED_ATTACH, ED_ATT_CHARSET,          attach_charset,        NULL },
  { ED_ATTACH, ED_ATT_NUMBER,           NULL,                  attach_number_num },
  { ED_ATTACH, ED_ATT_TREE,             attach_tree,           NULL },
  { -1, -1, NULL, NULL },
  // clang-format on
};

/**
 * AttachRenderCallbacks2 - Callbacks for Attachment Expandos
 *
 * @sa AttachFormatDef, ExpandoDataAttach, ExpandoDataBody, ExpandoDataGlobal
 */
const struct ExpandoRenderCallback AttachRenderCallbacks2[] = {
  // clang-format off
  { ED_BODY,   ED_BOD_CHARSET_CONVERT,  body_charset_convert,  NULL },
  { ED_BODY,   ED_BOD_DELETED,          body_deleted,          body_deleted_num },
  { ED_BODY,   ED_BOD_DESCRIPTION,      body_description,      NULL },
  { ED_BODY,   ED_BOD_MIME_ENCODING,    body_mime_encoding,    NULL },
  { ED_BODY,   ED_BOD_FILE,             body_file,             NULL },
  { ED_BODY,   ED_BOD_FILE_DISPOSITION, body_file_disposition, NULL },
  { ED_BODY,   ED_BOD_DISPOSITION,      body_disposition,      NULL },
  { ED_BODY,   ED_BOD_MIME_MAJOR,       body_mime_major,       NULL },
  { ED_BODY,   ED_BOD_MIME_MINOR,       body_mime_minor,       NULL },
  { ED_BODY,   ED_BOD_ATTACH_QUALIFIES, body_attach_qualifies, body_attach_qualifies_num },
  { ED_BODY,   ED_BOD_FILE_SIZE,        body_file_size,        body_file_size_num },
  { ED_BODY,   ED_BOD_TAGGED,           body_tagged,           body_tagged_num },
  { ED_BODY,   ED_BOD_UNLINK,           body_unlink,           body_unlink_num },
  { ED_BODY,   ED_BOD_ATTACH_COUNT,     NULL,                  body_attach_count_num },
  { -1, -1, NULL, NULL },
  // clang-format on
};

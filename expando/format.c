/**
 * @file
 * Simple string formatting
 *
 * @authors
 * Copyright (C) 2023 Richard Russon <rich@flatcap.org>
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
 * @page expando_format Simple string formatting
 *
 * Simple string formatting
 */

#include "config.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include "mutt/lib.h"
#include "format.h"
#include "mutt_thread.h"
#ifdef HAVE_ISWBLANK
#include <wctype.h>
#endif

/**
 * buf_justify - Justify a string
 * @param buf      String to justify
 * @param justify  Justification, e.g. #JUSTIFY_RIGHT
 * @param max_cols Number of columns to pad to
 * @param pad_char Character to fill with
 */
void buf_justify(struct Buffer *buf, enum FormatJustify justify, size_t max_cols, char pad_char)
{
  if (!buf || (pad_char == '\0'))
    return;

  size_t len = buf_len(buf);
  if (len >= max_cols)
    return;

  buf_alloc(buf, len + max_cols);

  max_cols -= len;

  switch (justify)
  {
    case JUSTIFY_LEFT:
    {
      memset(buf->dptr, pad_char, max_cols);
      break;
    }

    case JUSTIFY_CENTER:
    {
      if (max_cols > 1)
      {
        memmove(buf->data + (max_cols / 2), buf->data, len);
        memset(buf->data, pad_char, max_cols / 2);
      }
      memset(buf->data + len + (max_cols / 2), pad_char, (max_cols + 1) / 2);
      break;
    }

    case JUSTIFY_RIGHT:
    {
      memmove(buf->data + max_cols, buf->data, len);
      memset(buf->data, pad_char, max_cols);
      break;
    }
  }

  buf->dptr += max_cols;
  buf->dptr[0] = '\0';
}

/**
 * format_string - Format a string, like snprintf()
 * @param[out] buf       Buffer in which to save string
 * @param[in]  min_cols  Minimum number of screen columns to use
 * @param[in]  max_cols  Maximum number of screen columns to use
 * @param[in]  justify   Justification, e.g. #JUSTIFY_RIGHT
 * @param[in]  pad_char  Padding character
 * @param[in]  str       String to format
 * @param[in]  n         Number of bytes of string to format
 * @param[in]  arboreal  If true, string contains graphical tree characters
 * @retval obj Number of bytes and screen columns used
 *
 * This formats a string, a bit like sprintf(buf, "%-*.*s", min_cols, max_cols, str),
 * except that the max_cols refer to the number of character cells when printed.
 */
int format_string(struct Buffer *buf, int min_cols, int max_cols, enum FormatJustify justify,
                  char pad_char, const char *str, size_t n, bool arboreal)
{
  wchar_t wc = 0;
  int w = 0;
  size_t k = 0;
  char scratch[MB_LEN_MAX] = { 0 };
  mbstate_t mbstate1 = { 0 };
  mbstate_t mbstate2 = { 0 };
  bool escaped = false;
  int used_cols = 0;

  for (; (n > 0) && (k = mbrtowc(&wc, str, n, &mbstate1)); str += k, n -= k)
  {
    if ((k == ICONV_ILLEGAL_SEQ) || (k == ICONV_BUF_TOO_SMALL))
    {
      if ((k == ICONV_ILLEGAL_SEQ) && (errno == EILSEQ))
        memset(&mbstate1, 0, sizeof(mbstate1));

      k = (k == ICONV_ILLEGAL_SEQ) ? 1 : n;
      wc = ReplacementChar;
    }

    // How many screen cells will the character require?
    if (escaped || (CharsetIsUtf8 && mutt_mb_is_display_corrupting_utf8(wc)))
    {
      escaped = false;
      w = 0;
    }
    else if (arboreal && (wc == MUTT_SPECIAL_INDEX))
    {
      escaped = true;
      w = 0;
    }
    else if (arboreal && (wc < MUTT_TREE_MAX))
    {
      w = 1; /* hack */
    }
    else if (iswspace(wc))
    {
      w = MAX(1, wcwidth(wc));
    }
    else
    {
      if (!IsWPrint(wc))
        wc = ReplacementChar;
      w = wcwidth(wc);
    }

    // It'll require _some_ space
    if (w >= 0)
    {
      if (w > max_cols)
        continue;
      size_t k2 = wcrtomb(scratch, wc, &mbstate2);
      if (k2 == ICONV_ILLEGAL_SEQ)
        continue; // LCOV_EXCL_LINE

      used_cols += w;

      min_cols -= w;
      max_cols -= w;
      buf_addstr_n(buf, scratch, k2);
    }
  }

  // How much space is left?
  w = min_cols;
  if (w > 0)
  {
    used_cols += w;
  }

  if (w > 0)
    buf_justify(buf, justify, buf_len(buf) + w, pad_char);

  return used_cols;
}

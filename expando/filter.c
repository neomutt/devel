/**
 * @file
 * Expando filtering
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
 * @page expando_filter Expando filtering
 *
 * Filter the rendered Expando through an external command.
 */

#include "config.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "expando.h"
#include "node.h"

struct ExpandoRenderData;

/**
 * check_for_pipe - Should the Expando be piped to an external command?
 * @param root Root Node
 * @retval true Yes, pipe it
 *
 * - Check the last Node is text
 * - Check for a trailing | (pipe) character
 */
bool check_for_pipe(struct ExpandoNode *root)
{
  if (!root)
    return false;

  struct ExpandoNode *last = node_last(root);
  if (!last || (last->type != ENT_TEXT))
    return false;

  size_t len = mutt_str_len(last->text);
  if (len < 1)
    return false;

  if (last->text[len - 1] != '|')
    return false;

  // Count any preceding backslashes
  int count = 0;
  for (int i = len - 2; i >= 0; i--)
  {
    if (last->text[i] == '\\')
      count++;
  }

  // The pipe character is escaped with a backslash
  if ((count % 2) != 0)
    return false;

  return true;
}

/**
 * filter_text - Filter the text through an external command
 * @param[in,out] buf      Text
 * @param[in]     env_list Environment
 *
 * The text is passed unchanged to the shell.
 * The first line of any output (minus the newline) is stored back in buf.
 */
void filter_text(struct Buffer *buf, char **env_list)
{
  // Trim the | (pipe) character
  size_t len = buf_len(buf);
  if (len == 0)
    return;

  if (buf->data[len - 1] == '|')
    buf->data[len - 1] = '\0';

  mutt_debug(LL_DEBUG3, "execute: %s\n", buf_string(buf));
  FILE *fp_filter = NULL;
  pid_t pid = filter_create(buf_string(buf), NULL, &fp_filter, NULL, env_list);
  if (pid < 0)
    return; // LCOV_EXCL_LINE

  buf_reset(buf);
  size_t n = fread(buf->data, 1, buf->dsize - 1, fp_filter);
  mutt_file_fclose(&fp_filter);
  buf_fix_dptr(buf);

  int rc = filter_wait(pid);
  if (rc != 0)
    mutt_debug(LL_DEBUG1, "filter cmd exited code %d\n", rc);

  if (n == 0)
  {
    mutt_debug(LL_DEBUG1, "error reading from filter: %s (errno=%d)\n",
               strerror(errno), errno);
    buf_reset(buf);
    return;
  }

  char *nl = (char *) buf_find_char(buf, '\n');
  if (nl)
    *nl = '\0';
  mutt_debug(LL_DEBUG3, "received: %s\n", buf_string(buf));
}

/**
 * expando_filter - Render an Expando and run the result through a filter
 * @param[in]  exp      Expando containing the expando tree
 * @param[in]  rdata    Render data
 * @param[in]  max_cols Number of screen columns (-1 means unlimited)
 * @param[in]  env_list Environment to pass to filter
 * @param[out] buf      Buffer in which to save string
 * @retval obj Number of bytes written to buf and screen columns used
 */
int expando_filter(const struct Expando *exp, const struct ExpandoRenderData *rdata,
                   int max_cols, char **env_list, struct Buffer *buf)
{
  if (!exp || !exp->node)
    return 0;

  struct ExpandoNode *node = exp->node;

  bool is_pipe = check_for_pipe(node);
  int old_cols = max_cols;
  if (is_pipe)
    max_cols = -1;

  int rc = expando_render(exp, rdata, max_cols, buf);

  if (!is_pipe)
    return rc;

  filter_text(buf, env_list);

  // Strictly truncate to size
  size_t width = 0;
  size_t bytes = mutt_wstr_trunc(buf_string(buf), buf_len(buf), old_cols, &width);
  buf->data[bytes] = '\0';

  return width;
}

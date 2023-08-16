/**
 * @file
 * Auto-completion helpers
 *
 * @authors
 * Copyright (C) 2022 Richard Russon <rich@flatcap.org>
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
 * @page complete_helpers Auto-completion helpers
 *
 * Auto-completion helpers
 */

#include "config.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "mutt/lib.h"
#include "config/lib.h"
#include "core/lib.h"
#include "lib.h"
#include "index/lib.h"
#include "menu/lib.h"
#include "notmuch/lib.h"
#include "functions.h"
#include "keymap.h"
#include "menu/type.h"

/**
 * matches_ensure_morespace - Allocate more space for auto-completion
 * @param cd       Completion Data
 * @param new_size Space required
 */
static void matches_ensure_morespace(struct CompletionData *cd, int new_size)
{
  if (new_size <= (cd->match_list_len - 2))
    return;

  new_size = ROUND_UP(new_size + 2, 512);

  mutt_mem_realloc(&cd->match_list, new_size * sizeof(char *));
  memset(&cd->match_list[cd->match_list_len], 0, new_size - cd->match_list_len);

  cd->match_list_len = new_size;
}

/**
 * candidate - Helper function for completion
 * @param cd   Completion Data
 * @param user User entered data for completion
 * @param src  Candidate for completion
 * @param dest Completion result gets here
 * @param dlen Length of dest buffer
 * @retval true If candidate string matches
 *
 * Changes the dest buffer if necessary/possible to aid completion.
 */
static bool candidate(struct CompletionData *cd, char *user, const char *src,
                      char *dest, size_t dlen)
{
  if (!dest || !user || !src)
    return false;

  if (strstr(src, user) != src)
    return false;

  matches_ensure_morespace(cd, cd->num_matched);
  cd->match_list[cd->num_matched++] = src;
  if (dest[0] == '\0')
  {
    mutt_str_copy(dest, src, dlen);
  }
  else
  {
    int l;
    for (l = 0; (src[l] != '\0') && (src[l] == dest[l]); l++)
      ; // do nothing

    dest[l] = '\0';
  }
  return true;
}

#ifdef USE_NOTMUCH
/**
 * complete_all_nm_tags - Pass a list of Notmuch tags to the completion code
 * @param cd Completion Data
 * @param pt List of all Notmuch tags
 * @retval  0 Success
 * @retval -1 Error
 */
static int complete_all_nm_tags(struct CompletionData *cd, const char *pt)
{
  struct Mailbox *m_cur = get_current_mailbox();
  int tag_count_1 = 0;
  int tag_count_2 = 0;
  int rc = -1;

  mutt_str_copy(cd->user_typed, pt, sizeof(cd->user_typed));
  memset(cd->match_list, 0, cd->match_list_len);
  memset(cd->completed, 0, sizeof(cd->completed));
  cd->free_match_strings = true;

  nm_db_longrun_init(m_cur, false);

  /* Work out how many tags there are. */
  if ((nm_get_all_tags(m_cur, NULL, &tag_count_1) != 0) || (tag_count_1 == 0))
    goto done;

  /* Get all the tags. */
  const char **nm_tags = mutt_mem_calloc(tag_count_1, sizeof(char *));
  if ((nm_get_all_tags(m_cur, nm_tags, &tag_count_2) != 0) || (tag_count_1 != tag_count_2))
  {
    completion_data_free_match_strings(cd);
    goto done;
  }

  /* Put them into the completion machinery. */
  for (int i = 0; i < tag_count_1; i++)
  {
    if (!candidate(cd, cd->user_typed, nm_tags[i], cd->completed, sizeof(cd->completed)))
      FREE(&nm_tags[i]);
  }

  matches_ensure_morespace(cd, cd->num_matched);
  cd->match_list[cd->num_matched++] = mutt_str_dup(cd->user_typed);
  rc = 0;

done:
  FREE(&nm_tags);
  nm_db_longrun_done(m_cur);
  return rc;
}
#endif

/**
 * mutt_command_complete - Complete a command name
 * @param cd      Completion Data
 * @param buf     Buffer for the result
 * @param pos     Cursor position in the buffer
 * @param numtabs Number of times the user has hit 'tab'
 * @retval 1 Success, a match
 * @retval 0 Error, no match
 */
int mutt_command_complete(struct CompletionData *cd, struct Buffer *buf, int pos, int numtabs)
{
  char *pt = buf->data;
  int spaces; /* keep track of the number of leading spaces on the line */

  SKIPWS(pt);
  spaces = pt - buf->data;

  pt = buf->data + pos - spaces;
  while ((pt > buf->data) && !isspace((unsigned char) *pt))
    pt--;

  if (pt == buf->data) /* complete cmd */
  {
    /* first TAB. Collect all the matches */
    if (numtabs == 1)
    {
      cd->num_matched = 0;
      mutt_str_copy(cd->user_typed, pt, sizeof(cd->user_typed));
      memset(cd->match_list, 0, cd->match_list_len);
      memset(cd->completed, 0, sizeof(cd->completed));

      struct Command *c = NULL;
      for (size_t num = 0, size = commands_array(&c); num < size; num++)
        candidate(cd, cd->user_typed, c[num].name, cd->completed, sizeof(cd->completed));
      matches_ensure_morespace(cd, cd->num_matched);
      cd->match_list[cd->num_matched++] = cd->user_typed;

      /* All matches are stored. Longest non-ambiguous string is ""
       * i.e. don't change 'buf'. Fake successful return this time */
      if (cd->user_typed[0] == '\0')
        return 1;
    }

    if ((cd->completed[0] == '\0') && (cd->user_typed[0] != '\0'))
      return 0;

    /* cd->num_matched will _always_ be at least 1 since the initial
     * user-typed string is always stored */
    if ((numtabs == 1) && (cd->num_matched == 2))
    {
      snprintf(cd->completed, sizeof(cd->completed), "%s", cd->match_list[0]);
    }
    else if ((numtabs > 1) && (cd->num_matched > 2))
    {
      /* cycle through all the matches */
      snprintf(cd->completed, sizeof(cd->completed), "%s",
               cd->match_list[(numtabs - 2) % cd->num_matched]);
    }

    /* return the completed command */
    buf_strcpy(buf, cd->completed);
  }
  else if (buf_startswith(buf, "set") || buf_startswith(buf, "unset") ||
           buf_startswith(buf, "reset") || buf_startswith(buf, "toggle"))
  { /* complete variables */
    static const char *const prefixes[] = { "no", "inv", "?", "&", 0 };

    pt++;
    /* loop through all the possible prefixes (no, inv, ...) */
    if (buf_startswith(buf, "set"))
    {
      for (int num = 0; prefixes[num]; num++)
      {
        if (mutt_str_startswith(pt, prefixes[num]))
        {
          pt += mutt_str_len(prefixes[num]);
          break;
        }
      }
    }

    /* first TAB. Collect all the matches */
    if (numtabs == 1)
    {
      cd->num_matched = 0;
      mutt_str_copy(cd->user_typed, pt, sizeof(cd->user_typed));
      memset(cd->match_list, 0, cd->match_list_len);
      memset(cd->completed, 0, sizeof(cd->completed));

      struct HashElem *he = NULL;
      struct HashElem **he_list = get_elem_list(NeoMutt.sub->cs);
      for (size_t i = 0; he_list[i]; i++)
      {
        he = he_list[i];
        const int type = DTYPE(he->type);

        if ((type == DT_SYNONYM) || (type & DT_DEPRECATED))
          continue;

        candidate(cd, cd->user_typed, he->key.strkey, cd->completed, sizeof(cd->completed));
      }
      FREE(&he_list);

      matches_ensure_morespace(cd, cd->num_matched);
      cd->match_list[cd->num_matched++] = cd->user_typed;

      /* All matches are stored. Longest non-ambiguous string is ""
       * i.e. don't change 'buf'. Fake successful return this time */
      if (cd->user_typed[0] == '\0')
        return 1;
    }

    if ((cd->completed[0] == 0) && cd->user_typed[0])
      return 0;

    /* cd->num_matched will _always_ be at least 1 since the initial
     * user-typed string is always stored */
    if ((numtabs == 1) && (cd->num_matched == 2))
    {
      snprintf(cd->completed, sizeof(cd->completed), "%s", cd->match_list[0]);
    }
    else if ((numtabs > 1) && (cd->num_matched > 2))
    {
      /* cycle through all the matches */
      snprintf(cd->completed, sizeof(cd->completed), "%s",
               cd->match_list[(numtabs - 2) % cd->num_matched]);
    }

    strncpy(pt, cd->completed, buf->data + buf->dsize - pt - spaces);
    buf_fix_dptr(buf);
  }
  else if (buf_startswith(buf, "exec"))
  {
    const enum MenuType mtype = menu_get_current_type();
    const struct MenuFuncOp *funcs = km_get_table(mtype);
    if (!funcs && (mtype != MENU_PAGER))
      funcs = OpGeneric;

    pt++;
    /* first TAB. Collect all the matches */
    if (numtabs == 1)
    {
      cd->num_matched = 0;
      mutt_str_copy(cd->user_typed, pt, sizeof(cd->user_typed));
      memset(cd->match_list, 0, cd->match_list_len);
      memset(cd->completed, 0, sizeof(cd->completed));
      for (int num = 0; funcs[num].name; num++)
        candidate(cd, cd->user_typed, funcs[num].name, cd->completed, sizeof(cd->completed));
      /* try the generic menu */
      if ((mtype != MENU_PAGER) && (mtype != MENU_GENERIC))
      {
        funcs = OpGeneric;
        for (int num = 0; funcs[num].name; num++)
          candidate(cd, cd->user_typed, funcs[num].name, cd->completed,
                    sizeof(cd->completed));
      }
      matches_ensure_morespace(cd, cd->num_matched);
      cd->match_list[cd->num_matched++] = cd->user_typed;

      /* All matches are stored. Longest non-ambiguous string is ""
       * i.e. don't change 'buf'. Fake successful return this time */
      if (cd->user_typed[0] == '\0')
        return 1;
    }

    if ((cd->completed[0] == '\0') && (cd->user_typed[0] != '\0'))
      return 0;

    /* cd->num_matched will _always_ be at least 1 since the initial
     * user-typed string is always stored */
    if ((numtabs == 1) && (cd->num_matched == 2))
    {
      snprintf(cd->completed, sizeof(cd->completed), "%s", cd->match_list[0]);
    }
    else if ((numtabs > 1) && (cd->num_matched > 2))
    {
      /* cycle through all the matches */
      snprintf(cd->completed, sizeof(cd->completed), "%s",
               cd->match_list[(numtabs - 2) % cd->num_matched]);
    }

    strncpy(pt, cd->completed, buf->data + buf->dsize - pt - spaces);
    buf_fix_dptr(buf);
  }
  else
  {
    return 0;
  }

  return 1;
}

/**
 * label_sort - Sort two label strings - Implements ::sort_t - @ingroup sort_api
 * @param a   First string
 * @param b   Second string
 * @param arg (not used)
 * @retval -1 a precedes b
 * @retval  0 a and b are identical
 * @retval  1 b precedes a
 */
static int label_sort(const void *a, const void *b, void *arg)
{
  return strcasecmp(*(const char **) a, *(const char **) b);
}

/**
 * mutt_label_complete - Complete a label name
 * @param cd      Completion Data
 * @param buf     Buffer for the result
 * @param numtabs Number of times the user has hit 'tab'
 * @retval 1 Success, a match
 * @retval 0 Error, no match
 */
int mutt_label_complete(struct CompletionData *cd, struct Buffer *buf, int numtabs)
{
  char *pt = buf->data;

  struct Mailbox *m_cur = get_current_mailbox();
  if (!m_cur || !m_cur->label_hash)
    return 0;

  SKIPWS(pt);

  /* first TAB. Collect all the matches */
  if (numtabs == 1)
  {
    struct HashElem *he = NULL;
    struct HashWalkState hws = { 0 };

    cd->num_matched = 0;
    mutt_str_copy(cd->user_typed, buf_string(buf), sizeof(cd->user_typed));
    memset(cd->match_list, 0, cd->match_list_len);
    memset(cd->completed, 0, sizeof(cd->completed));
    while ((he = mutt_hash_walk(m_cur->label_hash, &hws)))
      candidate(cd, cd->user_typed, he->key.strkey, cd->completed, sizeof(cd->completed));
    matches_ensure_morespace(cd, cd->num_matched);
    mutt_qsort_r(cd->match_list, cd->num_matched, sizeof(char *), label_sort, NULL);
    cd->match_list[cd->num_matched++] = cd->user_typed;

    /* All matches are stored. Longest non-ambiguous string is ""
     * i.e. don't change 'buf'. Fake successful return this time */
    if (cd->user_typed[0] == '\0')
      return 1;
  }

  if ((cd->completed[0] == '\0') && (cd->user_typed[0] != '\0'))
    return 0;

  /* cd->num_matched will _always_ be at least 1 since the initial
   * user-typed string is always stored */
  if ((numtabs == 1) && (cd->num_matched == 2))
  {
    snprintf(cd->completed, sizeof(cd->completed), "%s", cd->match_list[0]);
  }
  else if ((numtabs > 1) && (cd->num_matched > 2))
  {
    /* cycle through all the matches */
    snprintf(cd->completed, sizeof(cd->completed), "%s",
             cd->match_list[(numtabs - 2) % cd->num_matched]);
  }

  /* return the completed label */
  buf_strcpy(buf, cd->completed);

  return 1;
}

#ifdef USE_NOTMUCH
/**
 * mutt_nm_query_complete - Complete to the nearest notmuch tag
 * @param cd      Completion Data
 * @param buf     Buffer for the result
 * @param pos     Cursor position in the buffer
 * @param numtabs Number of times the user has hit 'tab'
 * @retval true  Success, a match
 * @retval false Error, no match
 *
 * Complete the nearest "tag:"-prefixed string previous to pos.
 */
bool mutt_nm_query_complete(struct CompletionData *cd, struct Buffer *buf, int pos, int numtabs)
{
  char *pt = buf->data;
  int spaces;

  SKIPWS(pt);
  spaces = pt - buf->data;

  pt = (char *) mutt_strn_rfind((char *) buf, pos, "tag:");
  if (pt)
  {
    pt += 4;
    if (numtabs == 1)
    {
      /* First TAB. Collect all the matches */
      complete_all_nm_tags(cd, pt);

      /* All matches are stored. Longest non-ambiguous string is ""
       * i.e. don't change 'buf'. Fake successful return this time.  */
      if (cd->user_typed[0] == '\0')
        return true;
    }

    if ((cd->completed[0] == '\0') && (cd->user_typed[0] != '\0'))
      return false;

    /* cd->num_matched will _always_ be at least 1 since the initial
     * user-typed string is always stored */
    if ((numtabs == 1) && (cd->num_matched == 2))
    {
      snprintf(cd->completed, sizeof(cd->completed), "%s", cd->match_list[0]);
    }
    else if ((numtabs > 1) && (cd->num_matched > 2))
    {
      /* cycle through all the matches */
      snprintf(cd->completed, sizeof(cd->completed), "%s",
               cd->match_list[(numtabs - 2) % cd->num_matched]);
    }

    /* return the completed query */
    strncpy(pt, cd->completed, buf->data + buf->dsize - pt - spaces);
  }
  else
  {
    return false;
  }

  return true;
}
#endif

#ifdef USE_NOTMUCH
/**
 * mutt_nm_tag_complete - Complete to the nearest notmuch tag
 * @param cd      Completion Data
 * @param buf     Buffer for the result
 * @param numtabs Number of times the user has hit 'tab'
 * @retval true  Success, a match
 * @retval false Error, no match
 *
 * Complete the nearest "+" or "-" -prefixed string previous to pos.
 */
bool mutt_nm_tag_complete(struct CompletionData *cd, struct Buffer *buf, int numtabs)
{
  if (!buf)
    return false;

  char *pt = buf->data;

  /* Only examine the last token */
  char *last_space = strrchr(buf->data, ' ');
  if (last_space)
    pt = (last_space + 1);

  /* Skip the +/- */
  if ((pt[0] == '+') || (pt[0] == '-'))
    pt++;

  if (numtabs == 1)
  {
    /* First TAB. Collect all the matches */
    complete_all_nm_tags(cd, pt);

    /* All matches are stored. Longest non-ambiguous string is ""
     * i.e. don't change 'buf'. Fake successful return this time.  */
    if (cd->user_typed[0] == '\0')
      return true;
  }

  if ((cd->completed[0] == '\0') && (cd->user_typed[0] != '\0'))
    return false;

  /* cd->num_matched will _always_ be at least 1 since the initial
   * user-typed string is always stored */
  if ((numtabs == 1) && (cd->num_matched == 2))
  {
    snprintf(cd->completed, sizeof(cd->completed), "%s", cd->match_list[0]);
  }
  else if ((numtabs > 1) && (cd->num_matched > 2))
  {
    /* cycle through all the matches */
    snprintf(cd->completed, sizeof(cd->completed), "%s",
             cd->match_list[(numtabs - 2) % cd->num_matched]);
  }

  /* return the completed query */
  strncpy(pt, cd->completed, buf->data + buf->dsize - pt);

  return true;
}
#endif

/**
 * mutt_var_value_complete - Complete a variable/value
 * @param cd  Completion Data
 * @param buf Buffer for the result
 * @param pos Cursor position in the buffer
 * @retval 1 Success
 * @retval 0 Failure
 */
int mutt_var_value_complete(struct CompletionData *cd, struct Buffer *buf, int pos)
{
  char *pt = buf->data;

  if (pt[0] == '\0')
    return 0;

  SKIPWS(pt);
  const int spaces = pt - buf->data;

  pt = buf->data + pos - spaces;
  while ((pt > buf->data) && !isspace((unsigned char) *pt))
    pt--;
  pt++;           /* move past the space */
  if (*pt == '=') /* abort if no var before the '=' */
    return 0;

  if (buf_startswith(buf, "set"))
  {
    char var[256] = { 0 };
    mutt_str_copy(var, pt, sizeof(var));
    /* ignore the trailing '=' when comparing */
    int vlen = mutt_str_len(var);
    if (vlen == 0)
      return 0;

    var[vlen - 1] = '\0';

    struct HashElem *he = cs_subset_lookup(NeoMutt.sub, var);
    if (!he)
      return 0; /* no such variable. */

    struct Buffer value = buf_make(256);
    struct Buffer pretty = buf_make(256);
    int rc = cs_subset_he_string_get(NeoMutt.sub, he, &value);
    if (CSR_RESULT(rc) == CSR_SUCCESS)
    {
      pretty_var(value.data, &pretty);
      snprintf(pt, buf->dsize - (pt - buf->data), "%s=%s", var, pretty.data);
      buf_dealloc(&value);
      buf_dealloc(&pretty);
      return 0;
    }
    buf_dealloc(&value);
    buf_dealloc(&pretty);
    return 1;
  }
  return 0;
}

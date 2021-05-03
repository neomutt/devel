/**
 * @file
 * Notmuch query functions
 *
 * @authors
 * Copyright (C) 2021 Austin Ray <austin@austinray.io>
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
 * @page nm_query Notmuch query functions
 *
 * Notmuch query functions
 *
 * @note All functions within this file MUST be unit testable.
 */

#include "config.h"
#include <stddef.h>
#include "mutt/lib.h"
#include "query.h"

/**
 * nm_parse_type_from_query - Parse a query type out of a query
 * @param buf   Buffer for URL
 * @retval Notmuch query type.  Default: #NM_QUERY_TYPE_MESGS
 *
 * If a user writes a query for a vfolder and includes a type= statement, that
 * type= will be encoded, which Notmuch will treat as part of the query=
 * statement. This method will remove the type= and return its corresponding
 * NmQueryType representation.
 */
enum NmQueryType nm_parse_type_from_query(char *buf)
{
  if (!buf)
    return NM_QUERY_TYPE_MESGS;

  // The six variations of how type= could appear.
  const char *variants[6] = { "&type=threads", "&type=messages",
                              "type=threads&", "type=messages&",
                              "type=threads",  "type=messages" };

  enum NmQueryType query_type = NM_QUERY_TYPE_MESGS;
  int variants_size = mutt_array_size(variants);
  for (int i = 0; i < variants_size; i++)
  {
    if (mutt_istr_find(buf, variants[i]) != NULL)
    {
      // variants[] is setup such that type can be determined via modulo 2.
      query_type = ((i % 2) == 0) ? NM_QUERY_TYPE_THREADS : NM_QUERY_TYPE_MESGS;

      mutt_istr_remall(buf, variants[i]);
    }
  }

  return query_type;
}

/**
 * nm_query_type_to_string - Turn a query type into a string
 * @param query_type Query type
 * @retval ptr String
 *
 * @note This is a static string and must not be freed.
 */
const char *nm_query_type_to_string(enum NmQueryType query_type)
{
  if (query_type == NM_QUERY_TYPE_THREADS)
    return "threads";
  return "messages";
}

/**
 * nm_string_to_query_type - Lookup a query type
 * @param str String to lookup
 * @retval num Query type, e.g. #NM_QUERY_TYPE_MESGS
 *
 * If there's an unknown query type, default to NM_QUERY_TYPE_MESGS.
 */
enum NmQueryType nm_string_to_query_type(const char *str)
{
  enum NmQueryType query_type = nm_string_to_query_type_mapper(str);

  if (query_type == NM_QUERY_TYPE_UNKNOWN)
  {
    mutt_error(_("failed to parse notmuch query type: %s"), NONULL(str));
    return NM_QUERY_TYPE_MESGS;
  }

  return query_type;
}

/**
 * nm_string_to_query_type_mapper - Lookup a query type
 *
 * @param str String to lookup
 * @retval num Query type
 * @retval #NM_QUERY_TYPE_UNKNOWN on error
 */
enum NmQueryType nm_string_to_query_type_mapper(const char *str)
{
  if (mutt_str_equal(str, "threads"))
    return NM_QUERY_TYPE_THREADS;
  if (mutt_str_equal(str, "messages"))
    return NM_QUERY_TYPE_MESGS;

  return NM_QUERY_TYPE_UNKNOWN;
}

/**
 * query_window_check_timebase - Checks if a given timebase string is valid
 * @param[in] timebase: string containing a time base
 * @retval true The given time base is valid
 *
 * This function returns whether a given timebase string is valid or not,
 * which is used to validate the user settable configuration setting:
 *
 *     nm_query_window_timebase
 */
static bool query_window_check_timebase(const char *timebase)
{
  if ((strcmp(timebase, "hour") == 0) || (strcmp(timebase, "day") == 0) ||
      (strcmp(timebase, "week") == 0) || (strcmp(timebase, "month") == 0) ||
      (strcmp(timebase, "year") == 0))
  {
    return true;
  }
  return false;
}

/**
 * nm_windowed_query_from_query - Windows `buf` with notmuch `date:` search term
 * @param[out] buf    allocated string buffer to receive the modified search query
 * @param[in]  buflen allocated maximum size of the buf string buffer
 * @param[in]  duration Duration of time between beginning and end for notmuch `date` search term
 * @param[in]  cur_pos  Current position of vfolder window
 * @param[in]  cur_search Current notmuch search
 * @param[in]  timebase Timebase for `date:` search term. Must be: `hour`,
 *                      `day`, `week`, `month`, or `year`
 * @retval NM_WINDOW_QUERY_SUCCESS  Prepended `buf` with `date:` search term
 * @retval NM_WINDOW_QUERY_INVALID_DURATION Duration out-of-range for search term. `buf` *not* prepended with `date:`
 * @retval NM_WINDOW_QUERY_INVALID_TIMEBASE Timebase isn't one of `hour`, `day`, `week`, `month`, or `year`
 *
 * This is where the magic of windowed queries happens. Taking a vfolder search
 * query string as parameter, it will use the following two user settings:
 *
 * - `duration` and
 * - `timebase`
 *
 * to amend given vfolder search window. Then using a third parameter:
 *
 * - `cur_pos`
 *
 * it will generate a proper notmuch `date:` parameter. For example, given a
 * duration of `2`, a timebase set to `week` and a position defaulting to `0`,
 * it will prepend to the 'tag:inbox' notmuch search query the following string:
 *
 * - `query`: `tag:inbox`
 * - `buf`:   `date:2week..now and tag:inbox`
 *
 * If the position is set to `4`, with `duration=3` and `timebase=month`:
 *
 * - `query`: `tag:archived`
 * - `buf`:   `date:12month..9month and tag:archived`
 *
 * The window won't be applied:
 *
 * - If the duration of the search query is set to `0` this function will be disabled
 *   and return NM_WINDOW_QUERY_INVALID_DURATION
 *
 * - If the timebase is invalid, it will return NM_WINDOW_QUERY_INVALID_TIMEBASE
 */
enum NmWindowQueryRc nm_windowed_query_from_query(char *buf, size_t buflen,
                                                  const short duration, const short cur_pos,
                                                  const char *cur_search, const char *timebase)
{
  // if the duration is a non positive integer, disable the window unless the
  // user explictly enables windowed queries.
  if (duration <= 0)
  {
    return NM_WINDOW_QUERY_INVALID_DURATION;
  }

  int beg = duration * (cur_pos + 1);
  int end = duration * cur_pos;

  if (!query_window_check_timebase(timebase))
  {
    return NM_WINDOW_QUERY_INVALID_TIMEBASE;
  }

  if (end == 0)
  {
    // Open-ended date allows mail from the future.
    // This may occur is the sender's time settings are off.
    snprintf(buf, buflen, "date:%d%s.. and %s", beg, timebase, cur_search);
  }
  else
  {
    snprintf(buf, buflen, "date:%d%s..%d%s and %s", beg, timebase, end, timebase, cur_search);
  }

  return NM_WINDOW_QUERY_SUCCESS;
}

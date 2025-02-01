/**
 * @file
 * Test code hub
 *
 * @authors
 * Copyright (C) 2018-2022 Pietro Cerutti <gahr@gahr.ch>
 * Copyright (C) 2019 Simon Symeonidis <lethaljellybean@gmail.com>
 * Copyright (C) 2019-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2021 Austin Ray <austin@austinray.io>
 * Copyright (C) 2021 Eric Blake <eblake@redhat.com>
 * Copyright (C) 2022 Michal Siedlaczek <michal@siedlaczek.me>
 * Copyright (C) 2023 Anna Figueiredo Gomes <navi@vlhl.dev>
 * Copyright (C) 2023 Rayford Shireman
 * Copyright (C) 2023-2024 Dennis Schön <mail@dennis-schoen.de>
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

void test_init(void);
void test_fini(void);

#include "config.h"
#define TEST_INIT test_init()
#define TEST_FINI test_fini()
#include "acutest.h"

/******************************************************************************
 * Add your test cases to this list.
 *****************************************************************************/
#define NEOMUTT_TEST_LIST                                                      \
  /* account */                                                                \
  NEOMUTT_TEST_ITEM(test_account_free)                                         \
  NEOMUTT_TEST_ITEM(test_account_mailbox_add)                                  \
  NEOMUTT_TEST_ITEM(test_account_mailbox_remove)                               \
  NEOMUTT_TEST_ITEM(test_account_new)                                          \
                                                                               \
  /* address */                                                                \
  NEOMUTT_TEST_ITEM(test_address_config)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_addr_cat)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_addr_cmp)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_addr_copy)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_addr_create)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_addr_for_display)                                \
  NEOMUTT_TEST_ITEM(test_mutt_addr_free)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_addr_new)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_addr_to_intl)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_addr_to_local)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_addr_valid_msgid)                                \
  NEOMUTT_TEST_ITEM(test_mutt_addr_write)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_append)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_clear)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_copy)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_count_recips)                           \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_dedupe)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_equal)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_parse)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_parse2)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_prepend)                                \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_qualify)                                \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_remove)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_remove_xrefs)                           \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_search)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_to_intl)                                \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_to_local)                               \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_write)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_write_list)                             \
  NEOMUTT_TEST_ITEM(test_mutt_addrlist_write_wrap)                             \
                                                                               \
  /* array */                                                                  \
  NEOMUTT_TEST_ITEM(test_mutt_array_api)                                       \
                                                                               \
  /* attach */                                                                 \
  NEOMUTT_TEST_ITEM(test_mutt_actx_add_attach)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_actx_add_body)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_actx_add_fp)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_actx_entries_free)                               \
  NEOMUTT_TEST_ITEM(test_mutt_actx_free)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_actx_new)                                        \
                                                                               \
  /* base64 */                                                                 \
  NEOMUTT_TEST_ITEM(test_mutt_b64_buffer_decode)                               \
  NEOMUTT_TEST_ITEM(test_mutt_b64_buffer_encode)                               \
  NEOMUTT_TEST_ITEM(test_mutt_b64_decode)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_b64_encode)                                      \
                                                                               \
  /* body */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_body_cmp_strict)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_body_free)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_body_new)                                        \
                                                                               \
  /* buffer */                                                                 \
  NEOMUTT_TEST_ITEM(test_buf_addch)                                            \
  NEOMUTT_TEST_ITEM(test_buf_addstr)                                           \
  NEOMUTT_TEST_ITEM(test_buf_addstr_n)                                         \
  NEOMUTT_TEST_ITEM(test_buf_add_printf)                                       \
  NEOMUTT_TEST_ITEM(test_buf_alloc)                                            \
  NEOMUTT_TEST_ITEM(test_buf_at)                                               \
  NEOMUTT_TEST_ITEM(test_buf_coll)                                             \
  NEOMUTT_TEST_ITEM(test_buf_concatn_path)                                     \
  NEOMUTT_TEST_ITEM(test_buf_concat_path)                                      \
  NEOMUTT_TEST_ITEM(test_buf_copy)                                             \
  NEOMUTT_TEST_ITEM(test_buf_dealloc)                                          \
  NEOMUTT_TEST_ITEM(test_buf_dequote_comment)                                  \
  NEOMUTT_TEST_ITEM(test_buf_find_char)                                        \
  NEOMUTT_TEST_ITEM(test_buf_find_string)                                      \
  NEOMUTT_TEST_ITEM(test_buf_fix_dptr)                                         \
  NEOMUTT_TEST_ITEM(test_buf_free)                                             \
  NEOMUTT_TEST_ITEM(test_buf_init)                                             \
  NEOMUTT_TEST_ITEM(test_buf_inline_replace)                                   \
  NEOMUTT_TEST_ITEM(test_buf_insert)                                           \
  NEOMUTT_TEST_ITEM(test_buf_istr_equal)                                       \
  NEOMUTT_TEST_ITEM(test_buf_is_empty)                                         \
  NEOMUTT_TEST_ITEM(test_buf_join_str)                                         \
  NEOMUTT_TEST_ITEM(test_buf_len)                                              \
  NEOMUTT_TEST_ITEM(test_buf_lower)                                            \
  NEOMUTT_TEST_ITEM(test_buf_new)                                              \
  NEOMUTT_TEST_ITEM(test_buf_pool_cleanup)                                     \
  NEOMUTT_TEST_ITEM(test_buf_pool_get)                                         \
  NEOMUTT_TEST_ITEM(test_buf_pool_release)                                     \
  NEOMUTT_TEST_ITEM(test_buf_printf)                                           \
  NEOMUTT_TEST_ITEM(test_buf_reset)                                            \
  NEOMUTT_TEST_ITEM(test_buf_rfind)                                            \
  NEOMUTT_TEST_ITEM(test_buf_seek)                                             \
  NEOMUTT_TEST_ITEM(test_buf_startswith)                                       \
  NEOMUTT_TEST_ITEM(test_buf_strcpy)                                           \
  NEOMUTT_TEST_ITEM(test_buf_strcpy_n)                                         \
  NEOMUTT_TEST_ITEM(test_buf_strdup)                                           \
  NEOMUTT_TEST_ITEM(test_buf_str_equal)                                        \
  NEOMUTT_TEST_ITEM(test_buf_substrcpy)                                        \
                                                                               \
  /* charset */                                                                \
  NEOMUTT_TEST_ITEM(test_mutt_ch_canonical_charset)                            \
  NEOMUTT_TEST_ITEM(test_mutt_ch_charset_lookup)                               \
  NEOMUTT_TEST_ITEM(test_mutt_ch_check)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_ch_check_charset)                                \
  NEOMUTT_TEST_ITEM(test_mutt_ch_choose)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_ch_chscmp)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_ch_convert_nonmime_string)                       \
  NEOMUTT_TEST_ITEM(test_mutt_ch_convert_string)                               \
  NEOMUTT_TEST_ITEM(test_mutt_ch_fgetconv)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_ch_fgetconv_close)                               \
  NEOMUTT_TEST_ITEM(test_mutt_ch_fgetconv_open)                                \
  NEOMUTT_TEST_ITEM(test_mutt_ch_fgetconvs)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_ch_get_default_charset)                          \
  NEOMUTT_TEST_ITEM(test_mutt_ch_get_langinfo_charset)                         \
  NEOMUTT_TEST_ITEM(test_mutt_ch_iconv)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_ch_iconv_lookup)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_ch_iconv_open)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_ch_lookup_add)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_ch_lookup_remove)                                \
  NEOMUTT_TEST_ITEM(test_mutt_ch_set_charset)                                  \
                                                                               \
  /* color */                                                                  \
  NEOMUTT_TEST_ITEM(test_ansi_color)                                           \
  NEOMUTT_TEST_ITEM(test_ansi_color_parse_single)                              \
  NEOMUTT_TEST_ITEM(test_attr_colors)                                          \
  NEOMUTT_TEST_ITEM(test_color_dump)                                           \
  NEOMUTT_TEST_ITEM(test_color_notify)                                         \
  NEOMUTT_TEST_ITEM(test_curses_colors)                                        \
  NEOMUTT_TEST_ITEM(test_merged_colors)                                        \
  NEOMUTT_TEST_ITEM(test_parse_attr_spec)                                      \
  NEOMUTT_TEST_ITEM(test_parse_color_colornnn)                                 \
  NEOMUTT_TEST_ITEM(test_parse_color_name)                                     \
  NEOMUTT_TEST_ITEM(test_parse_color_namedcolor)                               \
  NEOMUTT_TEST_ITEM(test_parse_color_pair)                                     \
  NEOMUTT_TEST_ITEM(test_parse_color_prefix)                                   \
  NEOMUTT_TEST_ITEM(test_parse_color_rrggbb)                                   \
  NEOMUTT_TEST_ITEM(test_quoted_colors)                                        \
  NEOMUTT_TEST_ITEM(test_simple_colors)                                        \
                                                                               \
  /* config */                                                                 \
  NEOMUTT_TEST_ITEM(test_config_account)                                       \
  NEOMUTT_TEST_ITEM(test_config_bool)                                          \
  NEOMUTT_TEST_ITEM(test_config_dump)                                          \
  NEOMUTT_TEST_ITEM(test_config_enum)                                          \
  NEOMUTT_TEST_ITEM(test_config_helpers)                                       \
  NEOMUTT_TEST_ITEM(test_config_initial)                                       \
  NEOMUTT_TEST_ITEM(test_config_long)                                          \
  NEOMUTT_TEST_ITEM(test_config_mbtable)                                       \
  NEOMUTT_TEST_ITEM(test_config_myvar)                                         \
  NEOMUTT_TEST_ITEM(test_config_number)                                        \
  NEOMUTT_TEST_ITEM(test_config_path)                                          \
  NEOMUTT_TEST_ITEM(test_config_quad)                                          \
  NEOMUTT_TEST_ITEM(test_config_regex)                                         \
  NEOMUTT_TEST_ITEM(test_config_set)                                           \
  NEOMUTT_TEST_ITEM(test_config_slist)                                         \
  NEOMUTT_TEST_ITEM(test_config_sort)                                          \
  NEOMUTT_TEST_ITEM(test_config_string)                                        \
  NEOMUTT_TEST_ITEM(test_config_subset)                                        \
  NEOMUTT_TEST_ITEM(test_config_synonym)                                       \
  NEOMUTT_TEST_ITEM(test_config_variable)                                      \
                                                                               \
  /* convert */                                                                \
  NEOMUTT_TEST_ITEM(test_mutt_convert_file_to)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_convert_file_from_to)                            \
  NEOMUTT_TEST_ITEM(test_mutt_update_content_info)                             \
  NEOMUTT_TEST_ITEM(test_mutt_get_content_info)                                \
                                                                               \
  /* core */                                                                   \
  NEOMUTT_TEST_ITEM(test_buf_mktemp_full)                                      \
  NEOMUTT_TEST_ITEM(test_config_cache)                                         \
  NEOMUTT_TEST_ITEM(test_dispatcher_get_retval_name)                           \
  NEOMUTT_TEST_ITEM(test_mutt_file_mkstemp_full)                               \
                                                                               \
  /* date */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_date_add_timeout)                                \
  NEOMUTT_TEST_ITEM(test_mutt_date_check_month)                                \
  NEOMUTT_TEST_ITEM(test_mutt_date_now)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_date_now_ms)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_date_gmtime)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_date_local_tz)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_date_localtime)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_date_localtime_format)                           \
  NEOMUTT_TEST_ITEM(test_mutt_date_localtime_format_locale)                    \
  NEOMUTT_TEST_ITEM(test_mutt_date_make_date)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_date_make_imap)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_date_make_time)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_date_make_tls)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_date_normalize_time)                             \
  NEOMUTT_TEST_ITEM(test_mutt_date_parse_date)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_date_parse_imap)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_date_sleep_ms)                                   \
                                                                               \
  /* editor */                                                                 \
  NEOMUTT_TEST_ITEM(test_editor_backspace)                                     \
  NEOMUTT_TEST_ITEM(test_editor_backward_char)                                 \
  NEOMUTT_TEST_ITEM(test_editor_backward_word)                                 \
  NEOMUTT_TEST_ITEM(test_editor_bol)                                           \
  NEOMUTT_TEST_ITEM(test_editor_buffer_is_empty)                               \
  NEOMUTT_TEST_ITEM(test_editor_case_word)                                     \
  NEOMUTT_TEST_ITEM(test_editor_delete_char)                                   \
  NEOMUTT_TEST_ITEM(test_editor_eol)                                           \
  NEOMUTT_TEST_ITEM(test_editor_forward_char)                                  \
  NEOMUTT_TEST_ITEM(test_editor_forward_word)                                  \
  NEOMUTT_TEST_ITEM(test_editor_kill_eol)                                      \
  NEOMUTT_TEST_ITEM(test_editor_kill_eow)                                      \
  NEOMUTT_TEST_ITEM(test_editor_kill_line)                                     \
  NEOMUTT_TEST_ITEM(test_editor_kill_whole_line)                               \
  NEOMUTT_TEST_ITEM(test_editor_kill_word)                                     \
  NEOMUTT_TEST_ITEM(test_editor_state)                                         \
  NEOMUTT_TEST_ITEM(test_editor_transpose_chars)                               \
                                                                               \
  /* email */                                                                  \
  NEOMUTT_TEST_ITEM(test_email_cmp_strict)                                     \
  NEOMUTT_TEST_ITEM(test_email_free)                                           \
  NEOMUTT_TEST_ITEM(test_email_get_size)                                       \
  NEOMUTT_TEST_ITEM(test_email_header_add)                                     \
  NEOMUTT_TEST_ITEM(test_email_header_find)                                    \
  NEOMUTT_TEST_ITEM(test_email_header_free)                                    \
  NEOMUTT_TEST_ITEM(test_email_header_set)                                     \
  NEOMUTT_TEST_ITEM(test_email_header_update)                                  \
  NEOMUTT_TEST_ITEM(test_email_new)                                            \
  NEOMUTT_TEST_ITEM(test_mutt_autocrypthdr_free)                               \
  NEOMUTT_TEST_ITEM(test_mutt_autocrypthdr_new)                                \
  NEOMUTT_TEST_ITEM(test_mutt_auto_subscribe)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_check_encoding)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_check_mime_type)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_extract_message_id)                              \
  NEOMUTT_TEST_ITEM(test_mutt_is_message_type)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_matches_ignore)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_parse_content_type)                              \
  NEOMUTT_TEST_ITEM(test_mutt_parse_mailto)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_parse_multipart)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_parse_part)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_read_mime_header)                                \
  NEOMUTT_TEST_ITEM(test_mutt_rfc822_parse_line)                               \
  NEOMUTT_TEST_ITEM(test_mutt_rfc822_parse_message)                            \
  NEOMUTT_TEST_ITEM(test_mutt_rfc822_read_header)                              \
  NEOMUTT_TEST_ITEM(test_mutt_rfc822_read_line)                                \
                                                                               \
  /* envelope */                                                               \
  NEOMUTT_TEST_ITEM(test_mutt_env_cmp_strict)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_env_free)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_env_merge)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_env_new)                                         \
  NEOMUTT_TEST_ITEM(test_mutt_env_to_intl)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_env_to_local)                                    \
                                                                               \
  /* envlist */                                                                \
  NEOMUTT_TEST_ITEM(test_envlist_free)                                         \
  NEOMUTT_TEST_ITEM(test_envlist_init)                                         \
  NEOMUTT_TEST_ITEM(test_envlist_set)                                          \
  NEOMUTT_TEST_ITEM(test_envlist_unset)                                        \
                                                                               \
  /* eqi */                                                                    \
  NEOMUTT_TEST_ITEM(test_eqi)                                                  \
                                                                               \
  /* expando */                                                                \
  NEOMUTT_TEST_ITEM(test_expando_colors_render)                                \
  NEOMUTT_TEST_ITEM(test_expando_complex_if_else)                              \
  NEOMUTT_TEST_ITEM(test_expando_conditional_date)                             \
  NEOMUTT_TEST_ITEM(test_expando_conditional_date_render)                      \
  NEOMUTT_TEST_ITEM(test_expando_conditional_date_render2)                     \
  NEOMUTT_TEST_ITEM(test_expando_config)                                       \
  NEOMUTT_TEST_ITEM(test_expando_date_render)                                  \
  NEOMUTT_TEST_ITEM(test_expando_emoji_text)                                   \
  NEOMUTT_TEST_ITEM(test_expando_empty_if_else)                                \
  NEOMUTT_TEST_ITEM(test_expando_empty_if_else_render)                         \
  NEOMUTT_TEST_ITEM(test_expando_expando)                                      \
  NEOMUTT_TEST_ITEM(test_expando_filter)                                       \
  NEOMUTT_TEST_ITEM(test_expando_formatted_expando)                            \
  NEOMUTT_TEST_ITEM(test_expando_format_number)                                \
  NEOMUTT_TEST_ITEM(test_expando_helpers)                                      \
  NEOMUTT_TEST_ITEM(test_expando_if_else_false_render)                         \
  NEOMUTT_TEST_ITEM(test_expando_if_else_true_render)                          \
  NEOMUTT_TEST_ITEM(test_expando_justify)                                      \
  NEOMUTT_TEST_ITEM(test_expando_nested_if_else)                               \
  NEOMUTT_TEST_ITEM(test_expando_nested_if_else_render)                        \
  NEOMUTT_TEST_ITEM(test_expando_new_if_else)                                  \
  NEOMUTT_TEST_ITEM(test_expando_node)                                         \
  NEOMUTT_TEST_ITEM(test_expando_node_condbool)                                \
  NEOMUTT_TEST_ITEM(test_expando_node_conddate)                                \
  NEOMUTT_TEST_ITEM(test_expando_node_condition_parse)                         \
  NEOMUTT_TEST_ITEM(test_expando_node_container)                               \
  NEOMUTT_TEST_ITEM(test_expando_node_expando)                                 \
  NEOMUTT_TEST_ITEM(test_expando_node_expando_format)                          \
  NEOMUTT_TEST_ITEM(test_expando_node_padding)                                 \
  NEOMUTT_TEST_ITEM(test_expando_node_text_parse)                              \
  NEOMUTT_TEST_ITEM(test_expando_old_if_else)                                  \
  NEOMUTT_TEST_ITEM(test_expando_padding)                                      \
  NEOMUTT_TEST_ITEM(test_expando_padding_render)                               \
  NEOMUTT_TEST_ITEM(test_expando_parser)                                       \
  NEOMUTT_TEST_ITEM(test_expando_parse_short_name)                             \
  NEOMUTT_TEST_ITEM(test_expando_percent_sign_text)                            \
  NEOMUTT_TEST_ITEM(test_expando_simple_expando)                               \
  NEOMUTT_TEST_ITEM(test_expando_simple_expando_render)                        \
  NEOMUTT_TEST_ITEM(test_expando_simple_text)                                  \
  NEOMUTT_TEST_ITEM(test_expando_two_char_expando)                             \
  NEOMUTT_TEST_ITEM(test_expando_two_char_expando_render)                      \
  NEOMUTT_TEST_ITEM(test_expando_unicode_padding)                              \
  NEOMUTT_TEST_ITEM(test_expando_validation)                                   \
                                                                               \
  /* file */                                                                   \
  NEOMUTT_TEST_ITEM(test_buf_file_expand_fmt_quote)                            \
  NEOMUTT_TEST_ITEM(test_buf_quote_filename)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_file_check_empty)                                \
  NEOMUTT_TEST_ITEM(test_mutt_file_chmod_add)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_file_chmod_add_stat)                             \
  NEOMUTT_TEST_ITEM(test_mutt_file_chmod_rm_stat)                              \
  NEOMUTT_TEST_ITEM(test_mutt_file_copy_bytes)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_file_copy_stream)                                \
  NEOMUTT_TEST_ITEM(test_mutt_file_decrease_mtime)                             \
  NEOMUTT_TEST_ITEM(test_mutt_file_expand_fmt)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_file_fclose)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_file_fopen)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_file_fsync_close)                                \
  NEOMUTT_TEST_ITEM(test_mutt_file_get_size)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_file_get_stat_timespec)                          \
  NEOMUTT_TEST_ITEM(test_mutt_file_iter_line)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_file_lock)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_file_map_lines)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_file_mkdir)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_file_open)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_file_read_keyword)                               \
  NEOMUTT_TEST_ITEM(test_mutt_file_read_line)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_file_rename)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_file_resolve_symlink)                            \
  NEOMUTT_TEST_ITEM(test_mutt_file_rmtree)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_file_safe_rename)                                \
  NEOMUTT_TEST_ITEM(test_mutt_file_sanitize_filename)                          \
  NEOMUTT_TEST_ITEM(test_mutt_file_sanitize_regex)                             \
  NEOMUTT_TEST_ITEM(test_mutt_file_set_mtime)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_file_stat_compare)                               \
  NEOMUTT_TEST_ITEM(test_mutt_file_stat_timespec_compare)                      \
  NEOMUTT_TEST_ITEM(test_mutt_file_symlink)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_file_timespec_compare)                           \
  NEOMUTT_TEST_ITEM(test_mutt_file_touch_atime)                                \
  NEOMUTT_TEST_ITEM(test_mutt_file_unlink)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_file_unlink_empty)                               \
  NEOMUTT_TEST_ITEM(test_mutt_file_unlock)                                     \
                                                                               \
  /* filter */                                                                 \
  NEOMUTT_TEST_ITEM(test_filter_create)                                        \
  NEOMUTT_TEST_ITEM(test_filter_create_fd)                                     \
  NEOMUTT_TEST_ITEM(test_filter_wait)                                          \
                                                                               \
  /* from */                                                                   \
  NEOMUTT_TEST_ITEM(test_is_from)                                              \
                                                                               \
  /* group */                                                                  \
  NEOMUTT_TEST_ITEM(test_mutt_group_match)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_add)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_add_addrlist)                          \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_add_regex)                             \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_cleanup)                               \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_clear)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_destroy)                               \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_init)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_remove_addrlist)                       \
  NEOMUTT_TEST_ITEM(test_mutt_grouplist_remove_regex)                          \
  NEOMUTT_TEST_ITEM(test_mutt_pattern_group)                                   \
                                                                               \
  /* gui */                                                                    \
  NEOMUTT_TEST_ITEM(test_mutt_str_expand_tabs)                                 \
  NEOMUTT_TEST_ITEM(test_window_reflow)                                        \
  NEOMUTT_TEST_ITEM(test_window_swap)                                          \
  NEOMUTT_TEST_ITEM(test_window_visible)                                       \
                                                                               \
  /* hash */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_hash_delete)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_hash_find)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_hash_find_bucket)                                \
  NEOMUTT_TEST_ITEM(test_mutt_hash_find_elem)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_hash_free)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_hash_insert)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_hash_int_delete)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_hash_int_find)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_hash_int_insert)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_hash_int_new)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_hash_new)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_hash_set_destructor)                             \
  NEOMUTT_TEST_ITEM(test_mutt_hash_typed_insert)                               \
  NEOMUTT_TEST_ITEM(test_mutt_hash_walk)                                       \
                                                                               \
  /* history */                                                                \
  NEOMUTT_TEST_ITEM(test_mutt_hist_add)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_hist_at_scratch)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_hist_cleanup)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_hist_init)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_hist_next)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_hist_prev)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_hist_read_file)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_hist_reset_state)                                \
  NEOMUTT_TEST_ITEM(test_mutt_hist_save_scratch)                               \
  NEOMUTT_TEST_ITEM(test_mutt_hist_search)                                     \
                                                                               \
  /* idna */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_idna_intl_to_local)                              \
  NEOMUTT_TEST_ITEM(test_mutt_idna_local_to_intl)                              \
  NEOMUTT_TEST_ITEM(test_mutt_idna_print_version)                              \
  NEOMUTT_TEST_ITEM(test_mutt_idna_to_ascii_lz)                                \
                                                                               \
  /* imap */                                                                   \
  NEOMUTT_TEST_ITEM(test_imap_msg_set)                                         \
                                                                               \
  /* list */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_list_clear)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_list_copy_tail)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_list_equal)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_list_find)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_list_free)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_list_free_type)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_list_insert_after)                               \
  NEOMUTT_TEST_ITEM(test_mutt_list_insert_head)                                \
  NEOMUTT_TEST_ITEM(test_mutt_list_insert_tail)                                \
  NEOMUTT_TEST_ITEM(test_mutt_list_match)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_list_str_split)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_list_write)                                      \
                                                                               \
  /* logging */                                                                \
  NEOMUTT_TEST_ITEM(test_log_disp_file)                                        \
  NEOMUTT_TEST_ITEM(test_log_disp_queue)                                       \
  NEOMUTT_TEST_ITEM(test_log_disp_terminal)                                    \
  NEOMUTT_TEST_ITEM(test_log_file_close)                                       \
  NEOMUTT_TEST_ITEM(test_log_file_open)                                        \
  NEOMUTT_TEST_ITEM(test_log_file_running)                                     \
  NEOMUTT_TEST_ITEM(test_log_file_set_filename)                                \
  NEOMUTT_TEST_ITEM(test_log_file_set_level)                                   \
  NEOMUTT_TEST_ITEM(test_log_file_set_version)                                 \
  NEOMUTT_TEST_ITEM(test_log_queue_add)                                        \
  NEOMUTT_TEST_ITEM(test_log_queue_empty)                                      \
  NEOMUTT_TEST_ITEM(test_log_queue_flush)                                      \
  NEOMUTT_TEST_ITEM(test_log_queue_get)                                        \
  NEOMUTT_TEST_ITEM(test_log_queue_set_max_size)                               \
                                                                               \
  /* mailbox */                                                                \
  NEOMUTT_TEST_ITEM(test_mailbox_changed)                                      \
  NEOMUTT_TEST_ITEM(test_mailbox_find)                                         \
  NEOMUTT_TEST_ITEM(test_mailbox_find_name)                                    \
  NEOMUTT_TEST_ITEM(test_mailbox_free)                                         \
  NEOMUTT_TEST_ITEM(test_mailbox_new)                                          \
  NEOMUTT_TEST_ITEM(test_mailbox_set_subset)                                   \
  NEOMUTT_TEST_ITEM(test_mailbox_size_add)                                     \
  NEOMUTT_TEST_ITEM(test_mailbox_size_sub)                                     \
  NEOMUTT_TEST_ITEM(test_mailbox_update)                                       \
                                                                               \
  /* mapping */                                                                \
  NEOMUTT_TEST_ITEM(test_mutt_map_get_name)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_map_get_value)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_map_get_value_n)                                 \
                                                                               \
  /* mbyte */                                                                  \
  NEOMUTT_TEST_ITEM(test_buf_mb_wcstombs)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_mb_charlen)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_mb_filter_unprintable)                           \
  NEOMUTT_TEST_ITEM(test_mutt_mb_get_initials)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_mb_is_display_corrupting_utf8)                   \
  NEOMUTT_TEST_ITEM(test_mutt_mb_is_lower)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_mb_is_shell_char)                                \
  NEOMUTT_TEST_ITEM(test_mutt_mb_mbstowcs)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_mb_wcswidth)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_mb_wcwidth)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_mb_width)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_mb_width_ceiling)                                \
                                                                               \
  /* md5 */                                                                    \
  NEOMUTT_TEST_ITEM(test_mutt_md5)                                             \
  NEOMUTT_TEST_ITEM(test_mutt_md5_bytes)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_md5_finish_ctx)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_md5_init_ctx)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_md5_process)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_md5_process_bytes)                               \
  NEOMUTT_TEST_ITEM(test_mutt_md5_toascii)                                     \
                                                                               \
  /* memory */                                                                 \
  NEOMUTT_TEST_ITEM(test_mutt_mem_calloc)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_mem_free)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_mem_malloc)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_mem_realloc)                                     \
                                                                               \
  /* neomutt */                                                                \
  NEOMUTT_TEST_ITEM(test_neomutt_account_add)                                  \
  NEOMUTT_TEST_ITEM(test_neomutt_account_remove)                               \
  NEOMUTT_TEST_ITEM(test_neomutt_free)                                         \
  NEOMUTT_TEST_ITEM(test_neomutt_mailboxlist_clear)                            \
  NEOMUTT_TEST_ITEM(test_neomutt_mailboxlist_get_all)                          \
  NEOMUTT_TEST_ITEM(test_neomutt_new)                                          \
                                                                               \
  /* notify */                                                                 \
  NEOMUTT_TEST_ITEM(test_notify_free)                                          \
  NEOMUTT_TEST_ITEM(test_notify_new)                                           \
  NEOMUTT_TEST_ITEM(test_notify_observer_add)                                  \
  NEOMUTT_TEST_ITEM(test_notify_observer_remove)                               \
  NEOMUTT_TEST_ITEM(test_notify_send)                                          \
  NEOMUTT_TEST_ITEM(test_notify_set_parent)                                    \
                                                                               \
  /* parameter */                                                              \
  NEOMUTT_TEST_ITEM(test_mutt_param_cmp_strict)                                \
  NEOMUTT_TEST_ITEM(test_mutt_param_delete)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_param_free)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_param_free_one)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_param_get)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_param_new)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_param_set)                                       \
                                                                               \
  /* parse */                                                                  \
  NEOMUTT_TEST_ITEM(test_command_set)                                          \
  NEOMUTT_TEST_ITEM(test_parse_extract_token)                                  \
  NEOMUTT_TEST_ITEM(test_parse_rc)                                             \
  NEOMUTT_TEST_ITEM(test_parse_set)                                            \
                                                                               \
  /* path */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_path_abbr_folder)                                \
  NEOMUTT_TEST_ITEM(test_mutt_path_basename)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_path_canon)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_path_dirname)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_path_escape)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_path_getcwd)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_path_realpath)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_path_tidy)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_path_tidy_dotdot)                                \
  NEOMUTT_TEST_ITEM(test_mutt_path_tidy_slash)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_path_tilde)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_path_to_absolute)                                \
                                                                               \
  /* pattern */                                                                \
  NEOMUTT_TEST_ITEM(test_mutt_pattern_comp)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_pattern_leak)                                    \
                                                                               \
  /* pfile */                                                                  \
  NEOMUTT_TEST_ITEM(test_pfile)                                                \
                                                                               \
  /* prex */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_prex_capture)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_prex_cleanup)                                    \
                                                                               \
  /* random */                                                                 \
  NEOMUTT_TEST_ITEM(test_mutt_rand64)                                          \
  NEOMUTT_TEST_ITEM(test_mutt_rand_base32)                                     \
                                                                               \
  /* regex */                                                                  \
  NEOMUTT_TEST_ITEM(test_mutt_regex_capture)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_regex_compile)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_regex_free)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_regex_match)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_regex_new)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_regexlist_add)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_regexlist_free)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_regexlist_match)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_regexlist_new)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_regexlist_remove)                                \
  NEOMUTT_TEST_ITEM(test_mutt_replacelist_add)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_replacelist_apply)                               \
  NEOMUTT_TEST_ITEM(test_mutt_replacelist_free)                                \
  NEOMUTT_TEST_ITEM(test_mutt_replacelist_match)                               \
  NEOMUTT_TEST_ITEM(test_mutt_replacelist_new)                                 \
  NEOMUTT_TEST_ITEM(test_mutt_replacelist_remove)                              \
                                                                               \
  /* rfc2047 */                                                                \
  NEOMUTT_TEST_ITEM(test_rfc2047_decode)                                       \
  NEOMUTT_TEST_ITEM(test_rfc2047_decode_addrlist)                              \
  NEOMUTT_TEST_ITEM(test_rfc2047_decode_envelope)                              \
  NEOMUTT_TEST_ITEM(test_rfc2047_encode)                                       \
  NEOMUTT_TEST_ITEM(test_rfc2047_encode_addrlist)                              \
  NEOMUTT_TEST_ITEM(test_rfc2047_encode_envelope)                              \
                                                                               \
  /* rfc2231 */                                                                \
  NEOMUTT_TEST_ITEM(test_rfc2231_decode_parameters)                            \
  NEOMUTT_TEST_ITEM(test_rfc2231_encode_string)                                \
                                                                               \
  /* signal */                                                                 \
  NEOMUTT_TEST_ITEM(test_mutt_sig_allow_interrupt)                             \
  NEOMUTT_TEST_ITEM(test_mutt_sig_block)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_sig_block_system)                                \
  NEOMUTT_TEST_ITEM(test_mutt_sig_empty_handler)                               \
  NEOMUTT_TEST_ITEM(test_mutt_sig_exit_handler)                                \
  NEOMUTT_TEST_ITEM(test_mutt_sig_init)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_sig_unblock)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_sig_unblock_system)                              \
                                                                               \
  /* slist */                                                                  \
  NEOMUTT_TEST_ITEM(test_slist_add_string)                                     \
  NEOMUTT_TEST_ITEM(test_slist_dup)                                            \
  NEOMUTT_TEST_ITEM(test_slist_equal)                                          \
  NEOMUTT_TEST_ITEM(test_slist_free)                                           \
  NEOMUTT_TEST_ITEM(test_slist_is_empty)                                       \
  NEOMUTT_TEST_ITEM(test_slist_is_member)                                      \
  NEOMUTT_TEST_ITEM(test_slist_parse)                                          \
  NEOMUTT_TEST_ITEM(test_slist_remove_string)                                  \
  NEOMUTT_TEST_ITEM(test_slist_to_buffer)                                      \
                                                                               \
  /* sort */                                                                   \
  NEOMUTT_TEST_ITEM(test_mutt_qsort_r)                                         \
                                                                               \
  /* string */                                                                 \
  NEOMUTT_TEST_ITEM(test_mutt_istr_equal)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_istr_find)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_istr_remall)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_istrn_cmp)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_istrn_equal)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_istrn_rfind)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_str_adjust)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_str_asprintf)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_str_atoi)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_str_atol)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_str_atos)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_str_atoui)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_str_atoul)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_str_atoull)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_str_coll)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_str_copy)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_str_dup)                                         \
  NEOMUTT_TEST_ITEM(test_mutt_str_equal)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_str_find_word)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_str_getenv)                                      \
  NEOMUTT_TEST_ITEM(test_mutt_str_hyphenate)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_str_inbox_cmp)                                   \
  NEOMUTT_TEST_ITEM(test_mutt_str_is_ascii)                                    \
  NEOMUTT_TEST_ITEM(test_mutt_str_is_email_wsp)                                \
  NEOMUTT_TEST_ITEM(test_mutt_str_len)                                         \
  NEOMUTT_TEST_ITEM(test_mutt_str_lower)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_str_lws_len)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_str_remove_trailing_ws)                          \
  NEOMUTT_TEST_ITEM(test_mutt_str_replace)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_str_sep)                                         \
  NEOMUTT_TEST_ITEM(test_mutt_str_skip_email_wsp)                              \
  NEOMUTT_TEST_ITEM(test_mutt_str_skip_whitespace)                             \
  NEOMUTT_TEST_ITEM(test_mutt_str_startswith)                                  \
  NEOMUTT_TEST_ITEM(test_mutt_str_sysexit)                                     \
  NEOMUTT_TEST_ITEM(test_mutt_str_upper)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_strn_copy)                                       \
  NEOMUTT_TEST_ITEM(test_mutt_strn_dup)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_strn_equal)                                      \
                                                                               \
  /* tags */                                                                   \
  NEOMUTT_TEST_ITEM(test_driver_tags_free)                                     \
  NEOMUTT_TEST_ITEM(test_driver_tags_get)                                      \
  NEOMUTT_TEST_ITEM(test_driver_tags_get_transformed)                          \
  NEOMUTT_TEST_ITEM(test_driver_tags_get_transformed_for)                      \
  NEOMUTT_TEST_ITEM(test_driver_tags_get_with_hidden)                          \
  NEOMUTT_TEST_ITEM(test_driver_tags_replace)                                  \
                                                                               \
  /* thread */                                                                 \
  NEOMUTT_TEST_ITEM(test_clean_references)                                     \
  NEOMUTT_TEST_ITEM(test_find_virtual)                                         \
  NEOMUTT_TEST_ITEM(test_insert_message)                                       \
  NEOMUTT_TEST_ITEM(test_is_descendant)                                        \
  NEOMUTT_TEST_ITEM(test_mutt_break_thread)                                    \
  NEOMUTT_TEST_ITEM(test_unlink_message)                                       \
                                                                               \
  /* url */                                                                    \
  NEOMUTT_TEST_ITEM(test_url_check_scheme)                                     \
  NEOMUTT_TEST_ITEM(test_url_free)                                             \
  NEOMUTT_TEST_ITEM(test_url_parse)                                            \
  NEOMUTT_TEST_ITEM(test_url_pct_decode)                                       \
  NEOMUTT_TEST_ITEM(test_url_pct_encode)                                       \
  NEOMUTT_TEST_ITEM(test_url_tobuffer)                                         \
  NEOMUTT_TEST_ITEM(test_url_tostring)

/******************************************************************************
 * You probably don't need to touch what follows.
 *****************************************************************************/
// clang-format off
#define NEOMUTT_TEST_ITEM(x) void x(void);
NEOMUTT_TEST_LIST
#if defined(USE_LZ4) || defined(USE_ZLIB) || defined(USE_ZSTD)
  NEOMUTT_TEST_ITEM(test_compress_common)
#endif
#ifdef USE_LZ4
  NEOMUTT_TEST_ITEM(test_compress_lz4)
#endif
#ifdef USE_NOTMUCH
  NEOMUTT_TEST_ITEM(test_nm_parse_type_from_query)
  NEOMUTT_TEST_ITEM(test_nm_query_type_to_string)
  NEOMUTT_TEST_ITEM(test_nm_string_to_query_type)
  NEOMUTT_TEST_ITEM(test_nm_string_to_query_type_mapper)
  NEOMUTT_TEST_ITEM(test_nm_windowed_query_from_query)
  NEOMUTT_TEST_ITEM(test_nm_tag_string_to_tags)
#endif
#ifdef USE_ZLIB
  NEOMUTT_TEST_ITEM(test_compress_zlib)
#endif
#ifdef USE_ZSTD
  NEOMUTT_TEST_ITEM(test_compress_zstd)
#endif
#if defined(HAVE_BDB) || defined(HAVE_GDBM) || defined(HAVE_KC) || defined(HAVE_LMDB) || defined(HAVE_QDBM) || defined(HAVE_ROCKSDB) || defined(HAVE_TC) || defined(HAVE_TDB)
  NEOMUTT_TEST_ITEM(test_store_store)
#endif
#ifdef HAVE_BDB
  NEOMUTT_TEST_ITEM(test_store_bdb)
#endif
#ifdef HAVE_GDBM
  NEOMUTT_TEST_ITEM(test_store_gdbm)
#endif
#ifdef HAVE_KC
  NEOMUTT_TEST_ITEM(test_store_kc)
#endif
#ifdef HAVE_LMDB
  NEOMUTT_TEST_ITEM(test_store_lmdb)
#endif
#ifdef HAVE_QDBM
  NEOMUTT_TEST_ITEM(test_store_qdbm)
#endif
#ifdef HAVE_ROCKSDB
  NEOMUTT_TEST_ITEM(test_store_rocksdb)
#endif
#ifdef HAVE_TDB
  NEOMUTT_TEST_ITEM(test_store_tdb)
#endif
#ifdef HAVE_TC
  NEOMUTT_TEST_ITEM(test_store_tc)
#endif
#undef NEOMUTT_TEST_ITEM

TEST_LIST = {
#define NEOMUTT_TEST_ITEM(x) { #x, x },
  NEOMUTT_TEST_LIST
#if defined(USE_LZ4) || defined(USE_ZLIB) || defined(USE_ZSTD)
NEOMUTT_TEST_ITEM(test_compress_common)
#endif
#ifdef USE_LZ4
  NEOMUTT_TEST_ITEM(test_compress_lz4)
#endif
#ifdef USE_NOTMUCH
  NEOMUTT_TEST_ITEM(test_nm_parse_type_from_query)
  NEOMUTT_TEST_ITEM(test_nm_query_type_to_string)
  NEOMUTT_TEST_ITEM(test_nm_string_to_query_type)
  NEOMUTT_TEST_ITEM(test_nm_string_to_query_type_mapper)
  NEOMUTT_TEST_ITEM(test_nm_windowed_query_from_query)
  NEOMUTT_TEST_ITEM(test_nm_tag_string_to_tags)
#endif
#ifdef USE_ZLIB
  NEOMUTT_TEST_ITEM(test_compress_zlib)
#endif
#ifdef USE_ZSTD
  NEOMUTT_TEST_ITEM(test_compress_zstd)
#endif
#if defined(HAVE_BDB) || defined(HAVE_GDBM) || defined(HAVE_KC) || defined(HAVE_LMDB) || defined(HAVE_QDBM) || defined(HAVE_ROCKSDB) || defined(HAVE_TC) || defined(HAVE_TDB)
  NEOMUTT_TEST_ITEM(test_store_store)
#endif
#ifdef HAVE_BDB
  NEOMUTT_TEST_ITEM(test_store_bdb)
#endif
#ifdef HAVE_GDBM
  NEOMUTT_TEST_ITEM(test_store_gdbm)
#endif
#ifdef HAVE_KC
  NEOMUTT_TEST_ITEM(test_store_kc)
#endif
#ifdef HAVE_LMDB
  NEOMUTT_TEST_ITEM(test_store_lmdb)
#endif
#ifdef HAVE_QDBM
  NEOMUTT_TEST_ITEM(test_store_qdbm)
#endif
#ifdef HAVE_ROCKSDB
  NEOMUTT_TEST_ITEM(test_store_rocksdb)
#endif
#ifdef HAVE_TDB
  NEOMUTT_TEST_ITEM(test_store_tdb)
#endif
#ifdef HAVE_TC
  NEOMUTT_TEST_ITEM(test_store_tc)
#endif
#undef NEOMUTT_TEST_ITEM
  { 0 }
};
// clang-format on

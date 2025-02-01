/**
 * @file
 * Test code for window_reflow()
 *
 * @authors
 * Copyright (C) 2019-2023 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2023 Dennis Schön <mail@dennis-schoen.de>
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

#define TEST_NO_MAIN
#include "config.h"
#include "acutest.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "mutt/lib.h"
#include "gui/lib.h"
#include "test_common.h"

typedef uint16_t MuttRedrawFlags;

#ifndef USE_DEBUG_WINDOW
void debug_win_dump(void)
{
}
#endif

struct MuttWindow *sbar_new(void)
{
  return NULL;
}

void menu_set_current_redraw_full(void)
{
}

void menu_set_current_redraw(MuttRedrawFlags redraw)
{
}

static const char *win_size(struct MuttWindow *win)
{
  if (!win)
    return "???";

  switch (win->size)
  {
    case MUTT_WIN_SIZE_FIXED:
      return "FIX";
    case MUTT_WIN_SIZE_MAXIMISE:
      return "MAX";
    case MUTT_WIN_SIZE_MINIMISE:
      return "MIN";
  }

  return "???";
}

static void win_serialise(struct MuttWindow *win, struct Buffer *buf)
{
  if (!mutt_window_is_visible(win))
    return;

  buf_add_printf(buf, "<%s {%dx,%dy} [%dC,%dR]", win_size(win), win->state.col_offset,
                 win->state.row_offset, win->state.cols, win->state.rows);

  struct MuttWindow *np = NULL;
  TAILQ_FOREACH(np, &win->children, entries)
  {
    win_serialise(np, buf);
  }

  buf_addstr(buf, ">");
}

void test_window_reflow(void)
{
  // void window_reflow(struct MuttWindow *win);

  {
    window_reflow(NULL);
    TEST_CHECK_(1, "window_reflow(NULL)");
  }

  // ---------------------------------------------------------------------------
  // Horizontal tests in a fixed root of 80x24

  TEST_CASE("Horizontal");
  {
    // Root containing 'fix 40'
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [40C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 40,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->req_cols = 40;

    mutt_window_add_child(root, fix1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing 'max'
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('min' containing ('fix 20'))
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MIN {0x,0y} [20C,24R]<FIX {0x,0y} [20C,24R]>>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *min1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MINIMISE, 0, 0);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 20,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    mutt_window_add_child(root, min1);
    mutt_window_add_child(min1, fix1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('min' containing ('fix 20' and 'inv'))
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MIN {0x,0y} [20C,24R]<FIX {0x,0y} [20C,24R]>>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *min1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MINIMISE, 0, 0);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 20,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *inv1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 20,
                                              MUTT_WIN_SIZE_UNLIMITED);
    inv1->state.visible = false;

    mutt_window_add_child(root, min1);
    mutt_window_add_child(min1, fix1);
    mutt_window_add_child(min1, inv1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('min' containing ('fix 20' and 'fix 10'))
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MIN {0x,0y} [30C,24R]<FIX {0x,0y} [20C,24R]><FIX {20x,0y} [10C,24R]>>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *min1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MINIMISE, 0, 0);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 20,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 10,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix2->state.rows = fix2->req_rows;
    fix2->state.cols = fix2->req_cols;

    mutt_window_add_child(root, min1);
    mutt_window_add_child(min1, fix1);
    mutt_window_add_child(min1, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 40' and 'fix 20')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [40C,24R]><FIX {40x,0y} [20C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 40,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 20,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix2->state.rows = fix2->req_rows;
    fix2->state.cols = fix2->req_cols;

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 35' and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [35C,24R]><MAX {35x,0y} [45C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, max1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 35', 'inv', 'max' and 'inv')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [35C,24R]><MAX {35x,0y} [45C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *inv1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    inv1->state.visible = false;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    struct MuttWindow *inv2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    inv2->state.visible = false;

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, inv1);
    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, inv2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' and 'fix 35')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [45C,24R]><FIX {45x,0y} [35C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, fix1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [40C,24R]><MAX {40x,0y} [40C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, max2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max', 'max', 'max' and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [20C,24R]><MAX {20x,0y} [20C,24R]><MAX {40x,0y} [20C,24R]><MAX {60x,0y} [20C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max3 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max4 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, max2);
    mutt_window_add_child(root, max3);
    mutt_window_add_child(root, max4);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 40', 'fix 30' and 'fix 30')
    // Too big to fit on screen
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [40C,24R]><FIX {40x,0y} [30C,24R]><FIX {70x,0y} [10C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 40,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 30,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix3 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 30,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, fix2);
    mutt_window_add_child(root, fix3);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 40', 'fix 60' and 'fix 20')
    // Too big to fit on screen (third is completely offscreen)
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [40C,24R]><FIX {40x,0y} [40C,24R]><FIX {80x,0y} [0C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 40,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 60,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix3 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 20,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, fix2);
    mutt_window_add_child(root, fix3);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 45' containing ('fix 10' and 'max') and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [45C,24R]<FIX {0x,0y} [10C,24R]><MAX {10x,0y} [35C,24R]>><MAX {45x,0y} [35C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 45,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 10,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(fix1, fix2);
    mutt_window_add_child(fix1, max1);
    mutt_window_add_child(root, max2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' containing ('max' and 'fix 10') and 'fix 35')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [45C,24R]<MAX {0x,0y} [35C,24R]><FIX {35x,0y} [10C,24R]>><FIX {45x,0y} [35C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 10,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(max1, max2);
    mutt_window_add_child(max1, fix1);
    mutt_window_add_child(root, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 35' containing ('max' and 'fix 10') and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [35C,24R]<MAX {0x,0y} [25C,24R]><FIX {25x,0y} [10C,24R]>><MAX {35x,0y} [45C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 10,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(fix1, max1);
    mutt_window_add_child(fix1, fix2);
    mutt_window_add_child(root, max2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' containing ('max' and 'fix 10') and 'fix 35')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [45C,24R]<MAX {0x,0y} [35C,24R]><FIX {35x,0y} [10C,24R]>><FIX {45x,0y} [35C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 10,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_FIXED, 35,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(max1, max2);
    mutt_window_add_child(max1, fix1);
    mutt_window_add_child(root, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  // ---------------------------------------------------------------------------
  // Vertical tests in a fixed root of 80x24

  TEST_CASE("Vertical");
  {
    // Root containing 'fix 20'
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,20R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 20);
    fix1->req_rows = 20;

    mutt_window_add_child(root, fix1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing 'max'
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,24R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('min' containing ('fix 20'))
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MIN {0x,0y} [80C,20R]<FIX {0x,0y} [80C,20R]>>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *min1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MINIMISE, 0, 0);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 20);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    mutt_window_add_child(root, min1);
    mutt_window_add_child(min1, fix1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('min' containing ('fix 20' and 'inv'))
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MIN {0x,0y} [80C,20R]<FIX {0x,0y} [80C,20R]>>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *min1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MINIMISE, 0, 0);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 20);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *inv1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 20);
    inv1->state.visible = false;

    mutt_window_add_child(root, min1);
    mutt_window_add_child(min1, fix1);
    mutt_window_add_child(min1, inv1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('min' containing ('fix 10' and 'fix 5'))
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MIN {0x,0y} [80C,15R]<FIX {0x,0y} [80C,10R]><FIX {0x,10y} [80C,5R]>>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *min1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MINIMISE, 0, 0);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 5);
    fix2->state.rows = fix2->req_rows;
    fix2->state.cols = fix2->req_cols;

    mutt_window_add_child(root, min1);
    mutt_window_add_child(min1, fix1);
    mutt_window_add_child(min1, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 10' and 'fix 5')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,10R]><FIX {0x,10y} [80C,5R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 5);
    fix2->state.rows = fix2->req_rows;
    fix2->state.cols = fix2->req_cols;

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 15' and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,15R]><MAX {0x,15y} [80C,9R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 15);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, max1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 15', 'inv', 'max' and 'inv')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,15R]><MAX {0x,15y} [80C,9R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 15);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    struct MuttWindow *inv1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 5);
    inv1->state.visible = false;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    struct MuttWindow *inv2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    inv2->state.visible = false;

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, inv1);
    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, inv2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' and 'fix 15')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,9R]><FIX {0x,9y} [80C,15R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 15);
    fix1->state.rows = fix1->req_rows;
    fix1->state.cols = fix1->req_cols;

    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, fix1);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,12R]><MAX {0x,12y} [80C,12R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, max2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max', 'max', 'max' and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,6R]><MAX {0x,6y} [80C,6R]><MAX {0x,12y} [80C,6R]><MAX {0x,18y} [80C,6R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max3 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max4 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(root, max2);
    mutt_window_add_child(root, max3);
    mutt_window_add_child(root, max4);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 10', 'fix 12' and 'fix 15')
    // Too big to fit on screen
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,10R]><FIX {0x,10y} [80C,12R]><FIX {0x,22y} [80C,2R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 12);
    struct MuttWindow *fix3 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 15);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, fix2);
    mutt_window_add_child(root, fix3);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 20', 'fix 10' and 'fix 5')
    // Too big to fit on screen (third is completely offscreen)
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,20R]><FIX {0x,20y} [80C,4R]><FIX {0x,24y} [80C,0R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 20);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    struct MuttWindow *fix3 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 5);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(root, fix2);
    mutt_window_add_child(root, fix3);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 15' containing ('fix 5' and 'max') and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,15R]<FIX {0x,0y} [80C,5R]><MAX {0x,5y} [80C,10R]>><MAX {0x,15y} [80C,9R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 15);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 5);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(fix1, fix2);
    mutt_window_add_child(fix1, max1);
    mutt_window_add_child(root, max2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' containing ('max' and 'fix 10') and 'fix 12')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,12R]<MAX {0x,0y} [80C,2R]><FIX {0x,2y} [80C,10R]>><FIX {0x,12y} [80C,12R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 12);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(max1, max2);
    mutt_window_add_child(max1, fix1);
    mutt_window_add_child(root, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('fix 15' containing ('max' and 'fix 10') and 'max')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,15R]<MAX {0x,0y} [80C,5R]><FIX {0x,5y} [80C,10R]>><MAX {0x,15y} [80C,9R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 15);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, fix1);
    mutt_window_add_child(fix1, max1);
    mutt_window_add_child(fix1, fix2);
    mutt_window_add_child(root, max2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  {
    // Root containing ('max' containing ('max' and 'fix 10') and 'fix 5')
    static const char *expected = "<FIX {0x,0y} [80C,24R]<MAX {0x,0y} [80C,19R]<MAX {0x,0y} [80C,9R]><FIX {0x,9y} [80C,10R]>><FIX {0x,19y} [80C,5R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *fix1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 10);
    struct MuttWindow *fix2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 5);
    struct MuttWindow *max1 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *max2 = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                              MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(root, max1);
    mutt_window_add_child(max1, max2);
    mutt_window_add_child(max1, fix1);
    mutt_window_add_child(root, fix2);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }

  // ---------------------------------------------------------------------------
  // Index/Pager test in a fixed root of 80x24
  TEST_CASE("Index/Pager");
  {
    // (help, sidebar, pager_index_lines visible, status_on_top=no)
    static const char *expected = "<FIX {0x,0y} [80C,24R]<FIX {0x,0y} [80C,1R]><MAX {0x,1y} [80C,22R]<MAX {0x,1y} [80C,22R]<FIX {0x,1y} [15C,22R]><MAX {15x,1y} [65C,22R]<MIN {15x,1y} [65C,6R]<FIX {15x,1y} [65C,5R]><FIX {15x,6y} [65C,1R]>><MAX {15x,7y} [65C,16R]<MAX {15x,7y} [65C,15R]><FIX {15x,22y} [65C,1R]>>>>><FIX {0x,23y} [80C,1R]>>";

    struct MuttWindow *root = mutt_window_new(WT_ROOT, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED, 80, 24);
    root->state.rows = root->req_rows;
    root->state.cols = root->req_cols;

    struct MuttWindow *help = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                              MUTT_WIN_SIZE_FIXED,
                                              MUTT_WIN_SIZE_UNLIMITED, 1);
    struct MuttWindow *all_dialogs = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                     MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                                     MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *message = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                 MUTT_WIN_SIZE_FIXED,
                                                 MUTT_WIN_SIZE_UNLIMITED, 1);

    mutt_window_add_child(root, help);
    mutt_window_add_child(root, all_dialogs);
    mutt_window_add_child(root, message);

    struct MuttWindow *index_dlg = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                                   MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                                   MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *sidebar = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_HORIZONTAL,
                                                 MUTT_WIN_SIZE_FIXED, 15,
                                                 MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *right_cont = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                    MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                                    MUTT_WIN_SIZE_UNLIMITED);

    mutt_window_add_child(all_dialogs, index_dlg);
    mutt_window_add_child(index_dlg, sidebar);
    mutt_window_add_child(index_dlg, right_cont);

    struct MuttWindow *index_panel = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                     MUTT_WIN_SIZE_MINIMISE, 0, 0);
    struct MuttWindow *index = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                               MUTT_WIN_SIZE_FIXED,
                                               MUTT_WIN_SIZE_UNLIMITED, 5);
    struct MuttWindow *index_bar = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                   MUTT_WIN_SIZE_FIXED,
                                                   MUTT_WIN_SIZE_UNLIMITED, 1);

    mutt_window_add_child(index_panel, index);
    mutt_window_add_child(index_panel, index_bar);

    struct MuttWindow *pager_panel = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                     MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                                     MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *pager = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                               MUTT_WIN_SIZE_MAXIMISE, MUTT_WIN_SIZE_UNLIMITED,
                                               MUTT_WIN_SIZE_UNLIMITED);
    struct MuttWindow *pager_bar = mutt_window_new(WT_CUSTOM, MUTT_WIN_ORIENT_VERTICAL,
                                                   MUTT_WIN_SIZE_FIXED,
                                                   MUTT_WIN_SIZE_UNLIMITED, 1);

    mutt_window_add_child(pager_panel, pager);
    mutt_window_add_child(pager_panel, pager_bar);

    mutt_window_add_child(right_cont, index_panel);
    mutt_window_add_child(right_cont, pager_panel);

    window_reflow(root);

    struct Buffer *buf = buf_pool_get();
    win_serialise(root, buf);
    TEST_CHECK_STR_EQ(buf_string(buf), expected);

    buf_pool_release(&buf);
    mutt_window_free(&root);
  }
}

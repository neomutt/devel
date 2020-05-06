/**
 * @file
 * Test code for mutt_addr_for_display()
 *
 * @authors
 * Copyright (C) 2019 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2019 Pietro Cerutti <gahr@gahr.ch>
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
#include "mutt/lib.h"
#include "address/lib.h"
#include "test_common.h"

void test_mutt_addr_for_display(void)
{
  // const char *mutt_addr_for_display(const struct Address *a);

  {
    TEST_CHECK(!mutt_addr_for_display(NULL));
  }

  { /* integration */
    char per[64] = "bobby bob";
    char mbx[64] = "bob@bobsdomain";

    struct Address addr = {
      .personal = per,
      .mailbox = mbx,
      .group = 0,
      .is_intl = 0,
      .intl_checked = 0,
    };

    const char *expected = "bob@bobsdomain";
    const char *actual = mutt_addr_for_display(&addr);

    TEST_CHECK_STR_EQ(expected, actual);
  }
}

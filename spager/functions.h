/**
 * @file
 * Simple Pager Functions
 *
 * @authors
 * Copyright (C) 2024-2025 Richard Russon <rich@flatcap.org>
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

#ifndef MUTT_SPAGER_FUNCTIONS_H
#define MUTT_SPAGER_FUNCTIONS_H

struct MuttWindow;

/**
 * @defgroup spager_function_api Simple Pager Function API
 * @ingroup dispatcher_api
 *
 * Prototype for a Simple Pager Function
 *
 * @param win Simple Pager Window
 * @param op  Operation to perform, e.g. OP_MAIN_LIMIT
 * @retval enum #FunctionRetval
 */
typedef int (*spager_function_t)(struct MuttWindow *win, int op);

/**
 * struct SimplePagerFunction - A NeoMutt function
 */
struct SimplePagerFunction
{
  int op;                       ///< Op code, e.g. OP_MAIN_LIMIT
  spager_function_t function;   ///< Function to call
};

int spager_function_dispatcher(struct MuttWindow *win, int op);

#endif /* MUTT_SPAGER_FUNCTIONS_H */

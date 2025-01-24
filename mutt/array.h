/**
 * @file
 * Linear Array data structure
 *
 * @authors
 * Copyright (C) 2020-2023 Pietro Cerutti <gahr@gahr.ch>
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
 * @page mutt_array Linear array API
 *
 * API to store contiguous elements.
 */

#ifndef MUTT_MUTT_ARRAY_H
#define MUTT_MUTT_ARRAY_H

#include <stdbool.h>
#include <string.h>
#include "memory.h"

/**
 * ARRAY_HEADROOM - Additional number of elements to reserve, to prevent frequent reallocations
 */
#define ARRAY_HEADROOM 25

/**
 * ARRAY_HEAD - Define a named struct for arrays of elements of a certain type
 * @param name Name of the resulting struct
 * @param type Type of the elements stored in the array
 */
#define ARRAY_HEAD(name, type)                                                 \
  struct name                                                                  \
  {                                                                            \
    size_t size;     /**< Number of items in the array */                      \
    size_t capacity; /**< Maximum number of items in the array */              \
    type *entries;   /**< A C array of the items */                            \
  }

/**
 * ARRAY_HEAD_INITIALIZER - Static initializer for arrays
 */
#define ARRAY_HEAD_INITIALIZER                                                 \
  { 0, 0, NULL }

/**
 * ARRAY_INIT - Initialize an array
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 */
#define ARRAY_INIT(head)                                                       \
  memset((head), 0, sizeof(*(head)))

/**
 * ARRAY_EMPTY - Check if an array is empty
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval true The array is empty
 * @retval false The array is not empty
 */
#define ARRAY_EMPTY(head)                                                      \
  ((head)->size == 0)

/**
 * ARRAY_SIZE - The number of elements stored
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval num Number of elements stored
 *
 * @note Because it is possible to add elements in the middle of the array, see
 *       ARRAY_SET(), the number returned by ARRAY_SIZE() can be larger than
 *       the number of elements actually stored. Holes are filled with zero at
 *       ARRAY_RESERVE() time and are left untouched by ARRAY_SHRINK().
 */
#define ARRAY_SIZE(head)                                                       \
  ((head)->size)

/**
 * ARRAY_CAPACITY - The number of elements the array can store without reallocation
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval num The capacity of the array
 */
#define ARRAY_CAPACITY(head)                                                   \
  ((head)->capacity)

/**
 * ARRAY_GET - Return the element at index
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param idx  Index, between 0 and ARRAY_SIZE()-1
 * @retval ptr  Pointer to the element at the given index
 * @retval NULL Index was out of bounds
 *
 * @note Because it is possible to add elements in the middle of the array, it
 *       is also possible to retrieve elements that weren't previously
 *       explicitly set. In that case, the memory returned is all zeroes.
 */
#define ARRAY_GET(head, idx)                                                   \
  ((head)->size > (idx) ? &(head)->entries[(idx)] : NULL)

/**
 * ARRAY_SET - Set an element in the array
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param idx  Index, between 0 and ARRAY_SIZE()-1
 * @param elem Element to copy
 * @retval true Element was inserted
 * @retval false Element was not inserted, array was full
 *
 * @note This method has the side effect of changing the array size,
 *       if the insertion happens after the last element.
 */
#define ARRAY_SET(head, idx, elem)                                             \
  (((head)->capacity > (idx)                                                   \
    ? true                                                                     \
    : ARRAY_RESERVE((head), (idx) + 1)),                                       \
   ARRAY_SET_NORESERVE((head), (idx), (elem)))

/**
 * ARRAY_FIRST - Convenience method to get the first element
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval ptr  Pointer to the first element
 * @retval NULL Array is empty
 */
#define ARRAY_FIRST(head)                                                      \
   ARRAY_GET((head), 0)

/**
 * ARRAY_LAST - Convenience method to get the last element
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval ptr  Pointer to the last element
 * @retval NULL Array is empty
 */
#define ARRAY_LAST(head)                                                       \
  (ARRAY_EMPTY((head))                                                         \
   ? NULL                                                                      \
   : ARRAY_GET((head), ARRAY_SIZE((head)) - 1))

/**
 * ARRAY_ADD - Add an element at the end of the array
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param elem Element to copy
 * @retval true  Element was added
 * @retval false Element was not added, array was full
 */
#define ARRAY_ADD(head, elem)                                                  \
  (((head)->capacity > (head)->size                                            \
    ? true                                                                     \
    : ARRAY_RESERVE((head), (head)->size + 1)),                                \
   ARRAY_ADD_NORESERVE((head), (elem)))

/**
 * ARRAY_SHRINK - Mark a number of slots at the end of the array as unused
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param num  Number of slots to mark as unused
 * @retval num New size of the array
 *
 * @note This method does not do any memory management and has no effect on the
 *       capacity nor the contents of the array. It is just a resize which only
 *       works downwards.
 */
#define ARRAY_SHRINK(head, num)                                                \
  ((head)->size -= MIN((num), (head)->size))

/**
 * ARRAY_ELEM_SIZE - Number of bytes occupied by an element of this array
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval num Number of bytes per element
 */
#define ARRAY_ELEM_SIZE(head)                                                  \
  (sizeof(*(head)->entries))

/**
 * ARRAY_RESERVE - Reserve memory for the array
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param num Number of elements to make room for
 * @retval num New capacity of the array
 */
#define ARRAY_RESERVE(head, num)                                               \
  (((head)->capacity > (num)) ?                                                \
       (head)->capacity :                                                      \
       ((mutt_mem_reallocarray(                                                \
         &(head)->entries, (num) + ARRAY_HEADROOM, ARRAY_ELEM_SIZE(head))),    \
        (memset((head)->entries + (head)->capacity, 0,                         \
                ((num) + ARRAY_HEADROOM - (head)->capacity) *                  \
                ARRAY_ELEM_SIZE(head))),                                       \
        ((head)->capacity = (num) + ARRAY_HEADROOM)))

/**
 * ARRAY_FREE - Release all memory
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @retval 0 Always
 */
#define ARRAY_FREE(head)                                                       \
  (FREE(&(head)->entries), (head)->size = (head)->capacity = 0)

/**
 * ARRAY_FOREACH - Iterate over all elements of the array
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 */
#define ARRAY_FOREACH(elem, head)                                              \
  ARRAY_FOREACH_FROM_TO(elem, (head), 0, (head)->size)

/**
 * ARRAY_FOREACH_FROM - Iterate from an index to the end
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param from Starting index (inclusive)
 *
 * @note The from index must be between 0 and ARRAY_SIZE(head)
 */
#define ARRAY_FOREACH_FROM(elem, head, from)                                   \
  ARRAY_FOREACH_FROM_TO(elem, (head), (from), (head)->size)

/**
 * ARRAY_FOREACH_TO - Iterate from the beginning to an index
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param to   Terminating index (exclusive)
 *
 * @note The to index must be between 0 and ARRAY_SIZE(head)
 */
#define ARRAY_FOREACH_TO(elem, head, to)                                       \
  ARRAY_FOREACH_FROM_TO(elem, (head), 0, (to))

/**
 * ARRAY_FOREACH_FROM_TO - Iterate between two indexes
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param from Starting index (inclusive)
 * @param to   Terminating index (exclusive)
 *
 * @note The from and to indexes must be between 0 and ARRAY_SIZE(head);
 *       the from index must not be bigger than to index.
 */
#define ARRAY_FOREACH_FROM_TO(elem, head, from, to)                            \
  for (size_t ARRAY_FOREACH_IDX_##elem = (from);                               \
       (ARRAY_FOREACH_IDX_##elem < (to)) &&                                    \
       (elem = ARRAY_GET((head), ARRAY_FOREACH_IDX_##elem));                   \
       ARRAY_FOREACH_IDX_##elem++)

/**
 * ARRAY_FOREACH_REVERSE - Iterate backwards over all elements of the array
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 */
#define ARRAY_FOREACH_REVERSE(elem, head)                                      \
  ARRAY_FOREACH_REVERSE_FROM_TO(elem, (head), (head)->size, 0)

/**
 * ARRAY_FOREACH_REVERSE_FROM - Iterate from an index to the beginning
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param from Starting index (inclusive)
 *
 * @note The from index must be between 0 and ARRAY_SIZE(head)
 */
#define ARRAY_FOREACH_REVERSE_FROM(elem, head, from)                           \
  ARRAY_FOREACH_REVERSE_FROM_TO(elem, (head), (from), 0)

/**
 * ARRAY_FOREACH_REVERSE_TO - Iterate from the end to an index
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param to   Terminating index (exclusive)
 *
 * @note The to index must be between 0 and ARRAY_SIZE(head)
 */
#define ARRAY_FOREACH_REVERSE_TO(elem, head, to)                               \
  ARRAY_FOREACH_REVERSE_FROM_TO(elem, (head), (head)->size, (to))

/**
 * ARRAY_FOREACH_REVERSE_FROM_TO - Iterate between two indexes
 * @param elem Variable to be used as pointer to the element at each iteration
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param from Starting index (inclusive)
 * @param to   Terminating index (exclusive)
 *
 * @note The from and to indexes must be between 0 and ARRAY_SIZE(head);
 *       the from index must not be smaller than to index.
 */
#define ARRAY_FOREACH_REVERSE_FROM_TO(elem, head, from, to)                    \
  for (size_t ARRAY_FOREACH_IDX_##elem = (from) - 1;                           \
       (ARRAY_FOREACH_IDX_##elem >= (to)) &&                                   \
       (elem = ARRAY_GET((head), ARRAY_FOREACH_IDX_##elem));                   \
       ARRAY_FOREACH_IDX_##elem--)

/**
 * ARRAY_IDX - Return the index of an element of the array
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param elem Pointer to an element of the array
 * @retval num The index of element in the array
 */
#define ARRAY_IDX(head, elem)                                                  \
  (elem - (head)->entries)

/**
 * ARRAY_REMOVE - Remove an entry from the array, shifting down the subsequent entries
 * @param head Pointer to a struct defined using ARRAY_HEAD()
 * @param elem Pointer to the element of the array to remove
 */
#define ARRAY_REMOVE(head, elem)                                               \
  (memmove((elem), (elem) + 1,                                                 \
           ARRAY_ELEM_SIZE((head)) *                                           \
           MAX(0, (ARRAY_SIZE((head)) - ARRAY_IDX((head), (elem)) - 1))),      \
   ARRAY_SHRINK((head), 1))

/**
 * ARRAY_SORT - Sort an array
 * @param head  Pointer to a struct defined using ARRAY_HEAD()
 * @param fn    Sort function, see ::sort_t
 * @param sdata Opaque argument to pass to sort function
 */
#define ARRAY_SORT(head, fn, sdata)                                            \
  ((head)->entries &&                                                          \
   (mutt_qsort_r((head)->entries, ARRAY_SIZE(head), ARRAY_ELEM_SIZE(head), (fn), (sdata)), true))

/******************************************************************************
 * Internal APIs
 *****************************************************************************/
#define ARRAY_SET_NORESERVE(head, idx, elem)                                   \
  ((head)->capacity > (idx)                                                    \
   ? (((head)->size = MAX((head)->size, ((idx) + 1))),                         \
      ((head)->entries[(idx)] = (elem)),                                       \
      true)                                                                    \
   : false)

#ifndef __COVERITY__
#define __coverity_escape__(x) 0
#endif
#define ARRAY_ADD_NORESERVE(head, elem)                                        \
  ((head)->capacity > (head)->size                                             \
   ? (((head)->entries[(head)->size++] = (elem)),                              \
     ((void)__coverity_escape__(elem), true))                                  \
   : ((void)__coverity_escape__(elem), false))

#endif /* MUTT_MUTT_ARRAY_H */

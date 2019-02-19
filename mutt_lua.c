/**
 * @file
 * Integrated Lua scripting
 *
 * @authors
 * Copyright (C) 2016 Richard Russon <rich@flatcap.org>
 * Copyright (C) 2016 Bernard Pratz <z+mutt+pub@m0g.net>
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
 * @page mutt_lua Integrated Lua scripting
 *
 * Integrated Lua scripting
 */

#include "config.h"
#include <lauxlib.h>
#include <limits.h>
#include <lua.h>
#include <lualib.h>
#include <stdbool.h>
#include <stdio.h>
#include "mutt/mutt.h"
#include "config/lib.h"
#include "email/lib.h"
#include "mutt.h"
#include "mutt_lua.h"
#include "globals.h"
#include "mutt_commands.h"
#include "mutt_options.h"
#include "muttlib.h"
#include "mx.h"
#include "myvar.h"

/**
 * handle_panic - Handle a panic in the Lua interpreter
 * @param l Lua State
 * @retval -1 Always
 */
static int handle_panic(lua_State *l)
{
  mutt_debug(LL_DEBUG1, "lua runtime panic: %s\n", lua_tostring(l, -1));
  mutt_error("Lua runtime panic: %s\n", lua_tostring(l, -1));
  lua_pop(l, 1);
  return -1;
}

/**
 * handle_error - Handle an error in the Lua interpreter
 * @param l Lua State
 * @retval -1 Always
 */
static int handle_error(lua_State *l)
{
  mutt_debug(LL_DEBUG1, "lua runtime error: %s\n", lua_tostring(l, -1));
  mutt_error("Lua runtime error: %s\n", lua_tostring(l, -1));
  lua_pop(l, 1);
  return -1;
}

/**
 * lua_mutt_call - Call a NeoMutt command by name
 * @param l Lua State
 * @retval >=0 Success
 * @retval -1 Error
 */
static int lua_mutt_call(lua_State *l)
{
  mutt_debug(LL_DEBUG2, " * lua_mutt_call()\n");
  struct Buffer token, expn, err;
  char buffer[LONG_STRING] = "";
  const struct Command *command = NULL;
  int rc = 0;

  mutt_buffer_init(&token);
  mutt_buffer_init(&expn);
  mutt_buffer_init(&err);

  err.dsize = STRING;
  err.data = mutt_mem_malloc(err.dsize);
  err.data[0] = '\0';

  if (lua_gettop(l) == 0)
  {
    luaL_error(l, "Error command argument required.");
    return -1;
  }

  command = mutt_command_get(lua_tostring(l, 1));
  if (!command)
  {
    luaL_error(l, "Error command %s not found.", lua_tostring(l, 1));
    return -1;
  }

  for (int i = 2; i <= lua_gettop(l); i++)
  {
    const char *s = lua_tostring(l, i);
    mutt_str_strncat(buffer, sizeof(buffer), s, mutt_str_strlen(s));
    mutt_str_strncat(buffer, sizeof(buffer), " ", 1);
  }

  expn.data = buffer;
  expn.dptr = buffer;
  expn.dsize = mutt_str_strlen(buffer);

  if (command->func(&token, &expn, command->data, &err))
  {
    luaL_error(l, "NeoMutt error: %s", err.data);
    rc = -1;
  }
  else
  {
    if (!lua_pushstring(l, err.data))
      handle_error(l);
    else
      rc++;
  }

  FREE(&err.data);

  return rc;
}

/**
 * lua_mutt_set - Set a NeoMutt variable
 * @param l Lua State
 * @retval  0 Success
 * @retval -1 Error
 */
static int lua_mutt_set(lua_State *l)
{
  const char *param = lua_tostring(l, -2);
  mutt_debug(LL_DEBUG2, " * lua_mutt_set(%s)\n", param);

  if (mutt_str_startswith(param, "my_", CASE_MATCH))
  {
    const char *val = lua_tostring(l, -1);
    myvar_set(param, val);
    return 0;
  }

  struct HashElem *he = cs_get_elem(Config, param);
  if (!he)
  {
    luaL_error(l, "NeoMutt parameter not found %s", param);
    return -1;
  }

  struct ConfigDef *cdef = he->data;

  int rc = 0;
  struct Buffer *err = mutt_buffer_alloc(STRING);

  switch (DTYPE(cdef->type))
  {
    case DT_ADDRESS:
    case DT_MBTABLE:
    case DT_REGEX:
    case DT_PATH:
    case DT_COMMAND:
    case DT_SORT:
    case DT_STRING:
    case DT_MAGIC:
    {
      const char *value = lua_tostring(l, -1);
      int rv = cs_he_string_set(Config, he, value, err);
      if (CSR_RESULT(rv) != CSR_SUCCESS)
        rc = -1;
      break;
    }
    case DT_NUMBER:
    case DT_QUAD:
    {
      const intptr_t value = lua_tointeger(l, -1);
      int rv = cs_he_native_set(Config, he, value, err);
      if (CSR_RESULT(rv) != CSR_SUCCESS)
        rc = -1;
      break;
    }
    case DT_BOOL:
    {
      const intptr_t value = lua_toboolean(l, -1);
      int rv = cs_he_native_set(Config, he, value, err);
      if (CSR_RESULT(rv) != CSR_SUCCESS)
        rc = -1;
      break;
    }
    default:
      luaL_error(l, "Unsupported NeoMutt parameter type %d for %s", DTYPE(cdef->type), param);
      rc = -1;
      break;
  }

  mutt_buffer_free(&err);
  return rc;
}

/**
 * lua_mutt_get - Get a NeoMutt variable
 * @param l Lua State
 * @retval  1 Success
 * @retval -1 Error
 */
static int lua_mutt_get(lua_State *l)
{
  const char *param = lua_tostring(l, -1);
  mutt_debug(LL_DEBUG2, " * lua_mutt_get(%s)\n", param);

  if (mutt_str_startswith(param, "my_", CASE_MATCH))
  {
    const char *mv = myvar_get(param);
    if (!mv)
    {
      luaL_error(l, "NeoMutt parameter not found %s", param);
      return -1;
    }

    lua_pushstring(l, mv);
    return 1;
  }

  struct HashElem *he = cs_get_elem(Config, param);
  if (!he)
  {
    mutt_debug(LL_DEBUG2, " * error\n");
    luaL_error(l, "NeoMutt parameter not found %s", param);
    return -1;
  }

  struct ConfigDef *cdef = he->data;

  switch (DTYPE(cdef->type))
  {
    case DT_ADDRESS:
    case DT_COMMAND:
    case DT_MAGIC:
    case DT_MBTABLE:
    case DT_PATH:
    case DT_REGEX:
    case DT_SORT:
    case DT_STRING:
    {
      struct Buffer *value = mutt_buffer_alloc(STRING);
      int rc = cs_he_string_get(Config, he, value);
      if (CSR_RESULT(rc) != CSR_SUCCESS)
      {
        mutt_buffer_free(&value);
        return -1;
      }

      struct Buffer *escaped = mutt_buffer_alloc(STRING);
      escape_string(escaped, value->data);
      lua_pushstring(l, escaped->data);
      mutt_buffer_free(&value);
      mutt_buffer_free(&escaped);
      return 1;
    }
    case DT_QUAD:
      lua_pushinteger(l, *(unsigned char *) cdef->var);
      return 1;
    case DT_NUMBER:
      lua_pushinteger(l, (signed short) *((unsigned long *) cdef->var));
      return 1;
    case DT_BOOL:
      lua_pushboolean(l, *((bool *) cdef->var));
      return 1;
    default:
      luaL_error(l, "NeoMutt parameter type %d unknown for %s", cdef->type, param);
      return -1;
  }
}

/**
 * lua_mutt_enter - Execute NeoMutt config from Lua
 * @param l Lua State
 * @retval >=0 Success
 * @retval -1  Error
 */
static int lua_mutt_enter(lua_State *l)
{
  mutt_debug(LL_DEBUG2, " * lua_mutt_enter()\n");
  struct Buffer token, err;
  char *buffer = mutt_str_strdup(lua_tostring(l, -1));
  int rc = 0;

  mutt_buffer_init(&err);
  mutt_buffer_init(&token);

  err.dsize = STRING;
  err.data = mutt_mem_malloc(err.dsize);

  if (mutt_parse_rc_line(buffer, &token, &err))
  {
    luaL_error(l, "NeoMutt error: %s", err.data);
    rc = -1;
  }
  else
  {
    if (!lua_pushstring(l, err.data))
      handle_error(l);
    else
      rc++;
  }

  FREE(&buffer);
  FREE(&err.data);

  return rc;
}

/**
 * lua_mutt_message - Display a message in Neomutt
 * @param l Lua State
 * @retval 0 Always
 */
static int lua_mutt_message(lua_State *l)
{
  mutt_debug(LL_DEBUG2, " * lua_mutt_message()\n");
  const char *msg = lua_tostring(l, -1);
  if (msg)
    mutt_message(msg);
  return 0;
}

/**
 * lua_mutt_error - Display an error in Neomutt
 * @param l Lua State
 * @retval 0 Always
 */
static int lua_mutt_error(lua_State *l)
{
  mutt_debug(LL_DEBUG2, " * lua_mutt_error()\n");
  const char *msg = lua_tostring(l, -1);
  if (msg)
    mutt_error(msg);
  return 0;
}

/**
 * lua_expose_command - Expose a NeoMutt command to the Lua interpreter
 * @param p   Lua state
 * @param cmd NeoMutt Command
 */
static void lua_expose_command(void *p, const struct Command *cmd)
{
  lua_State *l = (lua_State *) p;
  char buf[LONG_STRING];
  snprintf(buf, sizeof(buf), "mutt.command.%s = function (...); mutt.call('%s', ...); end",
           cmd->name, cmd->name);
  (void) luaL_dostring(l, buf);
}

static const luaL_Reg luaMuttDecl[] = {
  { "set", lua_mutt_set },       { "get", lua_mutt_get },
  { "call", lua_mutt_call },     { "enter", lua_mutt_enter },
  { "print", lua_mutt_message }, { "message", lua_mutt_message },
  { "error", lua_mutt_error },   { NULL, NULL },
};

#define lua_add_lib_member(LUA, TABLE, KEY, VALUE, DATATYPE_HANDLER)           \
  lua_pushstring(LUA, KEY);                                                    \
  DATATYPE_HANDLER(LUA, VALUE);                                                \
  lua_settable(LUA, TABLE);

/**
 * luaopen_mutt_decl - Declare some NeoMutt types to the Lua interpreter
 * @param l Lua State
 * @retval 1 Always
 */
static int luaopen_mutt_decl(lua_State *l)
{
  mutt_debug(LL_DEBUG2, " * luaopen_mutt()\n");
  luaL_newlib(l, luaMuttDecl);
  int lib_idx = lua_gettop(l);
  /*                  table_idx, key        value,               value's type */
  lua_add_lib_member(l, lib_idx, "VERSION", mutt_make_version(), lua_pushstring);
  lua_add_lib_member(l, lib_idx, "QUAD_YES", MUTT_YES, lua_pushinteger);
  lua_add_lib_member(l, lib_idx, "QUAD_NO", MUTT_NO, lua_pushinteger);
  lua_add_lib_member(l, lib_idx, "QUAD_ASKYES", MUTT_ASKYES, lua_pushinteger);
  lua_add_lib_member(l, lib_idx, "QUAD_ASKNO", MUTT_ASKNO, lua_pushinteger);
  return 1;
}

/**
 * luaopen_mutt - Expose a 'Mutt' object to the Lua interpreter
 * @param l Lua State
 */
static void luaopen_mutt(lua_State *l)
{
  luaL_requiref(l, "mutt", luaopen_mutt_decl, 1);
  (void) luaL_dostring(l, "mutt.command = {}");
  mutt_commands_apply((void *) l, &lua_expose_command);
}

/**
 * lua_init - Initialise a Lua State
 * @param[out] l Lua State
 * @retval true If successful
 */
static bool lua_init(lua_State **l)
{
  if (!l)
    return false;
  if (*l)
    return true;

  mutt_debug(LL_DEBUG2, " * lua_init()\n");
  *l = luaL_newstate();

  if (!*l)
  {
    mutt_error(_("Error: Couldn't load the lua interpreter"));
    return false;
  }

  lua_atpanic(*l, handle_panic);

  /* load various Lua libraries */
  luaL_openlibs(*l);
  luaopen_mutt(*l);

  return true;
}

/* Public API --------------------------------------------------------------- */

lua_State *Lua = NULL;

/**
 * mutt_lua_parse - Parse the 'lua' command - Implements ::command_t
 */
enum CommandResult mutt_lua_parse(struct Buffer *buf, struct Buffer *s,
                                  unsigned long data, struct Buffer *err)
{
  lua_init(&Lua);
  mutt_debug(LL_DEBUG2, " * mutt_lua_parse(%s)\n", buf->data);

  if (luaL_dostring(Lua, s->dptr))
  {
    mutt_debug(LL_DEBUG2, " * %s -> failure\n", s->dptr);
    mutt_buffer_printf(err, "%s: %s", s->dptr, lua_tostring(Lua, -1));
    /* pop error message from the stack */
    lua_pop(Lua, 1);
    return MUTT_CMD_ERROR;
  }
  mutt_debug(LL_DEBUG2, " * %s -> success\n", s->dptr);
  return MUTT_CMD_SUCCESS;
}

/**
 * mutt_lua_source_file - Parse the 'lua-source' command - Implements ::command_t
 */
enum CommandResult mutt_lua_source_file(struct Buffer *buf, struct Buffer *s,
                                        unsigned long data, struct Buffer *err)
{
  mutt_debug(LL_DEBUG2, " * mutt_lua_source()\n");

  lua_init(&Lua);

  char path[PATH_MAX];

  if (mutt_extract_token(buf, s, 0) != 0)
  {
    mutt_buffer_printf(err, _("source: error at %s"), s->dptr);
    return MUTT_CMD_ERROR;
  }
  if (MoreArgs(s))
  {
    mutt_buffer_printf(err, _("%s: too many arguments"), "source");
    return MUTT_CMD_WARNING;
  }
  mutt_str_strfcpy(path, buf->data, sizeof(path));
  mutt_expand_path(path, sizeof(path));

  if (luaL_dofile(Lua, path))
  {
    mutt_error(_("Couldn't source lua source: %s"), lua_tostring(Lua, -1));
    lua_pop(Lua, 1);
    return MUTT_CMD_ERROR;
  }
  return MUTT_CMD_SUCCESS;
}

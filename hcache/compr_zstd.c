/**
 * @file
 * Zstd header cache compression
 *
 * @authors
 * Copyright (C) 2019 Tino Reichardt <milky-neomutt@mcmilk.de>
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
 * @page hc_comp_zstd Zstandard compression
 *
 * Use Zstandard header cache compression for database backends.
 */

#include "config.h"
#include <stdio.h>
#include <zstd.h>
#include "mutt/lib.h"
#include "lib.h"
#include "compr.h"

/**
 * struct ComprZstdCtx - Private Zstd Compression Context
 */
struct ComprZstdCtx
{
  void *buf;         ///< Temporary buffer
  ZSTD_CCtx *cctx;   ///< Compression context
  ZSTD_DCtx *dctx;   ///< Decompression context
  ZSTD_CDict *cdict; ///< Compression dictionary
  ZSTD_DDict *ddict; ///< Decompression dictionary
};

/**
 * compr_zstd_open - Implements ComprOps::open()
 */
static void *compr_zstd_open(void)
{
  struct ComprZstdCtx *ctx = mutt_mem_malloc(sizeof(struct ComprZstdCtx));

  ctx->buf = mutt_mem_malloc(ZSTD_compressBound(1024 * 128));
  ctx->cctx = ZSTD_createCCtx();
  ctx->dctx = ZSTD_createDCtx();
  ctx->cdict = NULL;
  ctx->ddict = NULL;

  if (!ctx->cctx || !ctx->dctx)
  {
    FREE(ctx);
    return NULL;
  }

  if (C_HeaderCacheCompressDictionary)
  {
    FILE *fp = fopen(C_HeaderCacheCompressDictionary, "r");
    if (fp)
    {
      fseek(fp, 0, SEEK_END);
      long dsize = ftell(fp);
      mutt_mem_realloc(&ctx->buf, dsize);
      rewind(fp);
      size_t done = fread(ctx->buf, 1, dsize, fp);
      if (done == dsize)
      {
        ctx->cdict = ZSTD_createCDict(ctx->buf, dsize, C_HeaderCacheCompressLevel);
        ctx->ddict = ZSTD_createDDict(ctx->buf, dsize);
      }
      fclose(fp);
    }
  }

  return ctx;
}

/**
 * compr_zstd_compress - Implements ComprOps::compress()
 */
static void *compr_zstd_compress(void *cctx, const char *data, size_t dlen, size_t *clen)
{
  if (!cctx)
    return NULL;

  struct ComprZstdCtx *ctx = cctx;

  size_t ret;
  size_t len = ZSTD_compressBound(dlen);
  mutt_mem_realloc_msg(&ctx->buf, len, _("Out of memory, please use smaller Levels for Zstandard or take LZ4."));

  if (ctx->cdict)
    ret = ZSTD_compress_usingCDict(ctx->cctx, ctx->buf, len, data, dlen, ctx->cdict);
  else
    ret = ZSTD_compressCCtx(ctx->cctx, ctx->buf, len, data, dlen, C_HeaderCacheCompressLevel);

  if (ZSTD_isError(ret))
    return NULL;

  *clen = ret;

  return ctx->buf;
}

/**
 * compr_zstd_decompress - Implements ComprOps::decompress()
 */
static void *compr_zstd_decompress(void *cctx, const char *cbuf, size_t clen)
{
  struct ComprZstdCtx *ctx = cctx;

  if (!cctx || clen < 8)
    return NULL;

  size_t ret;
  size_t len = ZSTD_getFrameContentSize(cbuf, clen);
  mutt_mem_realloc(&ctx->buf, len);

  if (ctx->ddict)
    ret = ZSTD_decompress_usingDDict(ctx->dctx, ctx->buf, len, cbuf, clen, ctx->ddict);
  else
    ret = ZSTD_decompressDCtx(ctx->dctx, ctx->buf, len, cbuf, clen);

  if (ZSTD_isError(ret))
    return NULL;

  return ctx->buf;
}

/**
 * compr_zstd_close - Implements ComprOps::close()
 */
static void compr_zstd_close(void **cctx)
{
  if (!cctx || !*cctx)
    return;

  struct ComprZstdCtx *ctx = *cctx;

  if (ctx->cctx)
    ZSTD_freeCCtx(ctx->cctx);

  if (ctx->dctx)
    ZSTD_freeDCtx(ctx->dctx);

  if (ctx->cdict)
    ZSTD_freeCDict(ctx->cdict);

  if (ctx->ddict)
    ZSTD_freeDDict(ctx->ddict);

  if (ctx->buf)
    FREE(&ctx->buf);

  FREE(cctx);
}

HCACHE_COMPRESS_OPS(zstd)

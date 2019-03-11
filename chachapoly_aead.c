#include "chachapoly_aead.h"

#define __STDC_WANT_LIB_EXT1__ 1
#include "poly1305.h"
#include <math.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) &&                 \
    !defined(__WINDOWS__)
#define __WINDOWS__
#endif

#if defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>

#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#elif defined(__OpenBSD__)
#include <sys/endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/endian.h>
#define le32toh(x) letoh32(x)
#define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)
#include <sys/param.h>
#include <winsock2.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define htole32(x) (x)
#define le32toh(x) (x)

#define htole64(x) (x)
#define le64toh(x) (x)

#elif BYTE_ORDER == BIG_ENDIAN
#define htole32(x) __builtin_bswap32(x)
#define le32toh(x) __builtin_bswap32(x)

#define htole64(x) __builtin_bswap64(x)
#define le64toh(x) __builtin_bswap64(x)

#else
#error byte order not supported
#endif /* endif byteorder */
#else

#error platform not supported

#endif /* endif platform */

#ifndef HAVE_TIMINGSAFE_BCMP

int timingsafe_bcmp(const void *b1, const void *b2, size_t n) {
  const unsigned char *p1 = b1, *p2 = b2;
  int ret = 0;

  for (; n > 0; n--)
    ret |= *p1++ ^ *p2++;
  return (ret != 0);
}

#endif /* TIMINGSAFE_BCMP */

#ifndef HAVE_MEMSET_S
void memory_cleanse(void *p, size_t n) {
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
  memset(p, 0, n);
#endif
#endif
}

#else /* no memset_s available */
void memory_cleanse(void *p, size_t n) { (void)memset_s(p, n, 0, n); }
#endif

#define XOR(v, w) ((v) ^ (w))

int chacha20poly1305_init(struct chachapolyaead_ctx *ctx, const uint8_t *k_1,
                          int k_1_len, const uint8_t *k_2, int k_2_len) {
  if (k_1_len != CHACHA20_POLY1305_AEAD_KEY_LEN || k_2_len != CHACHA20_POLY1305_AEAD_KEY_LEN)
    return -1;
  chacha_keysetup(&ctx->main_ctx, k_1, 256);
  chacha_keysetup(&ctx->header_ctx, k_2, 256);
  ctx->cached_aad_seqnr = UINT64_MAX;
  return 0;
}

int chacha20poly1305_crypt(struct chachapolyaead_ctx *ctx, uint64_t seqnr,
                           uint8_t *dest, const uint8_t *src, uint32_t len,
                           int is_encrypt) {
  uint8_t seqbuf[8];
  const uint8_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0}; /* NB little-endian */
  uint64_t aad_chacha_nonce_hdr = 0;
  uint8_t expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
  int r = -1;
  int aad_pos = 0;

  uint64_t chacha_iv = htole64(seqnr);
  memset(poly_key, 0, sizeof(poly_key));
  chacha_ivsetup(&ctx->main_ctx, (uint8_t *)&chacha_iv, NULL);
  chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));

  if (!is_encrypt) {
    const uint8_t *tag = src + CHACHA20_POLY1305_AEAD_AAD_LEN + len;

    poly1305_auth(expected_tag, src, CHACHA20_POLY1305_AEAD_AAD_LEN + len, poly_key);
    if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
      r = -1;
      goto out;
    }
  }

// add AAD (encrypted length)
  aad_pos = seqnr % AAD_PACKAGES_PER_ROUND * CHACHA20_POLY1305_AEAD_AAD_LEN; // the current position in the keystream
  seqnr = floor(seqnr / (float)AAD_PACKAGES_PER_ROUND); // 21 x 3byte length packages fits in a ChaCha20 round
  if (ctx->cached_aad_seqnr != seqnr) {
      ctx->cached_aad_seqnr = seqnr;
      aad_chacha_nonce_hdr = htole64(seqnr);
      chacha_ivsetup(&ctx->header_ctx, (uint8_t *)&aad_chacha_nonce_hdr, NULL); // block counter 0
      chacha_encrypt_bytes(&ctx->header_ctx, NULL, ctx->aad_keystream_buffer, CHACHA20_ROUND_OUTPUT);
  }
  printf("(CRYPT) keystream at pos %d with seq %lld: %d %d %d\n", aad_pos, seqnr, ctx->aad_keystream_buffer[aad_pos+0], ctx->aad_keystream_buffer[aad_pos+1], ctx->aad_keystream_buffer[aad_pos+2]);
  // crypt the AAD (3 byte length)
  dest[0] = XOR(src[0], ctx->aad_keystream_buffer[aad_pos+0]);
  dest[1] = XOR(src[1], ctx->aad_keystream_buffer[aad_pos+1]);
  dest[2] = XOR(src[2], ctx->aad_keystream_buffer[aad_pos+2]);

  printf("(CRYPT) m: %d %d %d   <->   c: %d %d %d\n", (uint8_t)src[0], (uint8_t)src[1], (uint8_t)src[2], dest[0], dest[1], dest[2]);

  /* Set Chacha's block counter to 1 */
  chacha_ivsetup(&ctx->main_ctx, (uint8_t *)&chacha_iv, one);
  chacha_encrypt_bytes(&ctx->main_ctx, src + CHACHA20_POLY1305_AEAD_AAD_LEN, dest + CHACHA20_POLY1305_AEAD_AAD_LEN, len);

  /* If encrypting, calculate and append tag */
  if (is_encrypt) {
    poly1305_auth(dest + CHACHA20_POLY1305_AEAD_AAD_LEN + len, dest, CHACHA20_POLY1305_AEAD_AAD_LEN + len, poly_key);
  }
  r = 0;
out:
  memory_cleanse(expected_tag, sizeof(expected_tag));
  memory_cleanse(seqbuf, sizeof(seqbuf));
  memory_cleanse(&chacha_iv, sizeof(chacha_iv));
  memory_cleanse(poly_key, sizeof(poly_key));
  return r;
}

int chacha20poly1305_get_length(struct chachapolyaead_ctx *ctx,
                                uint32_t *len_out, uint64_t seqnr,
                                const uint8_t *ciphertext) {
  uint8_t buf[3], seqbuf[8];

  int pos = seqnr % AAD_PACKAGES_PER_ROUND * CHACHA20_POLY1305_AEAD_AAD_LEN;
  seqnr = floor(seqnr / (float)AAD_PACKAGES_PER_ROUND); /* 21 x 3byte length packages fits in a ChaCha20 round */
  if (ctx->cached_aad_seqnr != seqnr) {
    /* we need to calculate the 64 keystream bytes since we reached a new sequence number */
    ctx->cached_aad_seqnr = seqnr;
    seqnr = htole64(seqnr); // use LE for the nonce
    chacha_ivsetup(&ctx->header_ctx, (uint8_t *)&seqnr, NULL); // block counter 0
    chacha_encrypt_bytes(&ctx->header_ctx, NULL, ctx->aad_keystream_buffer, CHACHA20_ROUND_OUTPUT);
  }

  /* decrypt the ciphertext length by XORing the right position of the 64byte keystream cache with the ciphertext */
  *len_out = 0;
  *len_out = XOR(ciphertext[0], ctx->aad_keystream_buffer[pos+0]) |
             XOR(ciphertext[1], ctx->aad_keystream_buffer[pos+1]) << 8 |
             XOR(ciphertext[2], ctx->aad_keystream_buffer[pos+2]) << 16;

  printf("(LENGTH) keystream at pos %d with seq %lld: %d %d %d\n", pos, seqnr, ctx->aad_keystream_buffer[pos+0], ctx->aad_keystream_buffer[pos+1], ctx->aad_keystream_buffer[pos+2]);
  printf("(LENGTH) m: %d %d %d   <->  c: %d %d %d\n", (uint8_t)len_out[0], (uint8_t)len_out[1], (uint8_t)len_out[2], ciphertext[0], ciphertext[1], ciphertext[2]);
  /* convert to host endianness 32bit integer (only 24bit though) */
  *len_out = le32toh(*len_out);
  return 0;
}
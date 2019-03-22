#ifndef CHACHA20_POLY_AEAD_H
#define CHACHA20_POLY_AEAD_H

#include "chacha.h"

#define CHACHA_KEYLEN 32 /* 2 x 256 bit keys */
#define CHACHA20_POLY1305_AEAD_KEY_LEN 32
#define CHACHA20_POLY1305_AEAD_AAD_LEN 3 /* 3 bytes length */
#define CHACHA20_ROUND_OUTPUT 64         /* 64 bytes per round */
#define AAD_PACKAGES_PER_ROUND 21        /* 64 / 3 round down*/

struct chachapolyaead_ctx {
    struct chacha_ctx main_ctx, header_ctx;
    uint8_t aad_keystream_buffer[CHACHA20_ROUND_OUTPUT];
    uint64_t cached_aad_seqnr;
};

int chacha20poly1305_init(struct chachapolyaead_ctx* cpctx, const uint8_t* k_1, int k_1_len, const uint8_t* k_2, int k_2_len);
int chacha20poly1305_crypt(struct chachapolyaead_ctx* ctx, uint64_t seqnr, uint64_t seqnr_aad, int pos_aad, uint8_t* dest, size_t dest_len, const uint8_t* src, size_t srv_len, int is_encrypt);
int chacha20poly1305_get_length(struct chachapolyaead_ctx* ctx,
    uint32_t* len_out,
    uint64_t seqnr,
    const uint8_t* ciphertext);
#endif /* CHACHA20_POLY_AEAD_H */

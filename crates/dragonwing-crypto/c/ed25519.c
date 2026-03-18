/*
 * SPDX-License-Identifier: MIT
 *
 * Ed25519 Digital Signatures (RFC 8032)
 *
 * Compact implementation for embedded systems.
 * Based on TweetNaCl and ref10 implementations.
 *
 * This implementation prioritizes code size over speed, making it
 * suitable for resource-constrained microcontrollers.
 */

#include "ed25519.h"
#include <string.h>

/* We need SHA-512 for Ed25519. Use mbedTLS if available, otherwise minimal impl */
#if defined(MBEDTLS_SHA512_C) || defined(CONFIG_MBEDTLS)
#include <mbedtls/sha512.h>
#define HAVE_MBEDTLS_SHA512 1
#else
/* Minimal SHA-512 implementation included below */
#define HAVE_MBEDTLS_SHA512 0
#endif

/*
 * Field element representation: 
 * We use 32-bit limbs for better performance on Cortex-M33
 */
typedef int64_t gf[16];

/* Constants */
static const uint8_t D[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
    0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
    0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

static const uint8_t D2[32] = {
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
    0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
    0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24
};

static const uint8_t BASEPOINT_Y[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static const gf GF0 = {0};
static const gf GF1 = {1};

/* L = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/*
 * SHA-512 interface
 */
#if HAVE_MBEDTLS_SHA512

static void sha512(uint8_t *out, const uint8_t *m, size_t n)
{
    mbedtls_sha512(m, n, out, 0);
}

static void sha512_init(mbedtls_sha512_context *ctx)
{
    mbedtls_sha512_init(ctx);
    mbedtls_sha512_starts(ctx, 0);
}

static void sha512_update(mbedtls_sha512_context *ctx, const uint8_t *m, size_t n)
{
    mbedtls_sha512_update(ctx, m, n);
}

static void sha512_final(mbedtls_sha512_context *ctx, uint8_t *out)
{
    mbedtls_sha512_finish(ctx, out);
    mbedtls_sha512_free(ctx);
}

typedef mbedtls_sha512_context sha512_ctx;

#else
/* Minimal SHA-512 implementation */

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} sha512_ctx;

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_transform(sha512_ctx *ctx, const uint8_t *data)
{
    uint64_t W[80], a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = ((uint64_t)data[i*8] << 56) | ((uint64_t)data[i*8+1] << 48) |
               ((uint64_t)data[i*8+2] << 40) | ((uint64_t)data[i*8+3] << 32) |
               ((uint64_t)data[i*8+4] << 24) | ((uint64_t)data[i*8+5] << 16) |
               ((uint64_t)data[i*8+6] << 8) | data[i*8+7];
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(W[i-15], 1) ^ rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
        uint64_t s1 = rotr64(W[i-2], 19) ^ rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K512[i] + W[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha512_init(sha512_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i = 0, idx = (size_t)(ctx->count[0] & 0x7f);
    ctx->count[0] += len;
    if (ctx->count[0] < len) ctx->count[1]++;

    if (idx) {
        size_t n = 128 - idx;
        if (len < n) {
            memcpy(ctx->buffer + idx, data, len);
            return;
        }
        memcpy(ctx->buffer + idx, data, n);
        sha512_transform(ctx, ctx->buffer);
        i = n;
    }
    for (; i + 128 <= len; i += 128)
        sha512_transform(ctx, data + i);
    if (i < len)
        memcpy(ctx->buffer, data + i, len - i);
}

static void sha512_final(sha512_ctx *ctx, uint8_t *out)
{
    uint8_t pad[128];
    uint64_t bits[2];
    size_t idx = (size_t)(ctx->count[0] & 0x7f);

    bits[0] = (ctx->count[1] << 3) | (ctx->count[0] >> 61);
    bits[1] = ctx->count[0] << 3;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    if (idx < 112) {
        sha512_update(ctx, pad, 112 - idx);
    } else {
        sha512_update(ctx, pad, 240 - idx);
    }

    for (int i = 0; i < 8; i++) {
        pad[i] = (uint8_t)(bits[0] >> (56 - i*8));
        pad[8+i] = (uint8_t)(bits[1] >> (56 - i*8));
    }
    sha512_update(ctx, pad, 16);

    for (int i = 0; i < 8; i++) {
        out[i*8+0] = (uint8_t)(ctx->state[i] >> 56);
        out[i*8+1] = (uint8_t)(ctx->state[i] >> 48);
        out[i*8+2] = (uint8_t)(ctx->state[i] >> 40);
        out[i*8+3] = (uint8_t)(ctx->state[i] >> 32);
        out[i*8+4] = (uint8_t)(ctx->state[i] >> 24);
        out[i*8+5] = (uint8_t)(ctx->state[i] >> 16);
        out[i*8+6] = (uint8_t)(ctx->state[i] >> 8);
        out[i*8+7] = (uint8_t)(ctx->state[i]);
    }
}

static void sha512(uint8_t *out, const uint8_t *m, size_t n)
{
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, m, n);
    sha512_final(&ctx, out);
}

#endif /* HAVE_MBEDTLS_SHA512 */

/*
 * Field arithmetic for curve25519
 */

static void set25519(gf r, const gf a)
{
    for (int i = 0; i < 16; i++) r[i] = a[i];
}

static void car25519(gf o)
{
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i+1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    gf m, t;
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    
    for (int i = 0; i < 16; i++) {
        o[2*i] = t[i] & 0xff;
        o[2*i+1] = t[i] >> 8;
    }
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; i++)
        o[i] = n[2*i] + ((int64_t)n[2*i+1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b)
{
    int64_t t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++)
            t[i+j] += a[i] * b[j];
    for (int i = 0; i < 15; i++)
        t[i] += 38 * t[i+16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a)
{
    M(o, a, a);
}

static void inv25519(gf o, const gf i)
{
    gf c;
    set25519(c, i);
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4)
            M(c, c, i);
    }
    set25519(o, c);
}

static void pow2523(gf o, const gf i)
{
    gf c;
    set25519(c, i);
    for (int a = 250; a >= 0; a--) {
        S(c, c);
        if (a != 1)
            M(c, c, i);
    }
    set25519(o, c);
}

/*
 * Scalar multiplication modulo L
 */

static void modL(uint8_t *r, int64_t x[64])
{
    for (int i = 63; i >= 32; i--) {
        int64_t carry = 0;
        for (int j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    
    int64_t carry = 0;
    for (int j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    
    for (int j = 0; j < 32; j++)
        x[j] -= carry * L[j];
    
    for (int i = 0; i < 32; i++) {
        x[i+1] += x[i] >> 8;
        r[i] = x[i] & 255;
    }
}

static void reduce(uint8_t *r)
{
    int64_t x[64];
    for (int i = 0; i < 64; i++) x[i] = r[i];
    for (int i = 0; i < 64; i++) r[i] = 0;
    modL(r, x);
}

/*
 * Ed25519 point operations
 */

static void scalarmult(gf p[4], gf q[4], const uint8_t *s);

static void scalarbase(gf p[4], const uint8_t *s)
{
    gf q[4];
    unpack25519(q[1], BASEPOINT_Y);
    set25519(q[2], GF1);
    M(q[0], q[1], q[1]);
    
    gf t;
    unpack25519(t, D);
    M(t, q[0], t);
    Z(q[0], q[0], q[2]);
    A(t, t, q[2]);
    M(t, q[0], t);
    pow2523(t, t);
    M(q[0], t, q[0]);
    
    /* Complete point recovery */
    S(t, q[0]);
    M(t, t, q[1]);
    M(t, t, q[1]);
    M(q[0], q[0], t);
    M(q[0], q[0], q[1]);
    pow2523(t, t);
    M(q[0], q[0], t);
    M(q[0], q[0], q[1]);
    M(q[0], q[0], q[1]);
    M(q[0], q[0], q[1]);
    
    /* Set X coordinate with correct sign */
    uint8_t check[32];
    pack25519(check, q[0]);
    if (check[0] & 1)
        Z(q[0], GF0, q[0]);
    
    set25519(q[3], GF0);
    M(q[3], q[0], q[1]);
    
    scalarmult(p, q, s);
}

static void add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    unpack25519(t, D2);
    M(c, c, t);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);
    
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

static void cswap(gf p[4], gf q[4], uint8_t b)
{
    for (int i = 0; i < 4; i++)
        sel25519(p[i], q[i], b);
}

static void scalarmult(gf p[4], gf q[4], const uint8_t *s)
{
    set25519(p[0], GF0);
    set25519(p[1], GF1);
    set25519(p[2], GF1);
    set25519(p[3], GF0);
    
    for (int i = 255; i >= 0; i--) {
        uint8_t b = (s[i/8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

static void pack(uint8_t *r, gf p[4])
{
    gf tx, ty, zi;
    inv25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack25519(r, ty);
    r[31] ^= (tx[0] & 1) << 7;
}

static int unpackneg(gf r[4], const uint8_t *p)
{
    gf t, chk, num, den, den2, den4, den6;
    
    set25519(r[2], GF1);
    unpack25519(r[1], p);
    S(num, r[1]);
    unpack25519(t, D);
    M(den, num, t);
    Z(num, num, r[2]);
    A(den, r[2], den);
    
    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);
    
    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);
    
    S(chk, r[0]);
    M(chk, chk, den);
    if (!memcmp(chk, num, sizeof(gf))) {
        Z(r[0], GF0, r[0]);
    }
    
    S(chk, r[0]);
    M(chk, chk, den);
    if (memcmp(chk, num, sizeof(gf)))
        return -1;
    
    uint8_t rp;
    pack25519((uint8_t*)&rp, r[0]);
    if ((rp & 1) == (p[31] >> 7))
        Z(r[0], GF0, r[0]);
    
    M(r[3], r[0], r[1]);
    return 0;
}

/*
 * Public API
 */

int ed25519_init(void)
{
    return 0;
}

void ed25519_get_pubkey(uint8_t public_key[32], const uint8_t secret_key[32])
{
    uint8_t hash[64];
    gf p[4];
    
    sha512(hash, secret_key, 32);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    
    scalarbase(p, hash);
    pack(public_key, p);
}

void ed25519_create_keypair(uint8_t public_key[32], const uint8_t secret_key[32])
{
    ed25519_get_pubkey(public_key, secret_key);
}

void ed25519_sign(uint8_t signature[64],
                  const uint8_t *message, size_t message_len,
                  const uint8_t secret_key[32],
                  const uint8_t public_key[32])
{
    uint8_t hash[64], hram[64];
    gf p[4];
    int64_t x[64];
    sha512_ctx ctx;
    
    sha512(hash, secret_key, 32);
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    
    sha512_init(&ctx);
    sha512_update(&ctx, hash + 32, 32);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, signature);
    
    reduce(signature);
    scalarbase(p, signature);
    pack(signature, p);
    
    sha512_init(&ctx);
    sha512_update(&ctx, signature, 32);
    sha512_update(&ctx, public_key, 32);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, hram);
    
    reduce(hram);
    
    for (int i = 0; i < 64; i++) x[i] = 0;
    for (int i = 0; i < 32; i++) x[i] = signature[32 + i];
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            x[i+j] += hram[i] * (int64_t)hash[j];
    
    modL(signature + 32, x);
}

int ed25519_verify(const uint8_t signature[64],
                   const uint8_t *message, size_t message_len,
                   const uint8_t public_key[32])
{
    uint8_t check[32], hram[64];
    gf p[4], q[4];
    sha512_ctx ctx;
    
    if (signature[63] & 224)
        return 0;
    
    if (unpackneg(q, public_key))
        return 0;
    
    sha512_init(&ctx);
    sha512_update(&ctx, signature, 32);
    sha512_update(&ctx, public_key, 32);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, hram);
    
    reduce(hram);
    scalarmult(p, q, hram);
    
    scalarbase(q, signature + 32);
    add(p, q);
    pack(check, p);
    
    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= check[i] ^ signature[i];
    
    return diff == 0;
}

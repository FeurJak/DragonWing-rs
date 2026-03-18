/*
 * SPDX-License-Identifier: MIT
 *
 * X25519 Key Agreement (RFC 7748)
 *
 * Compact implementation for embedded systems.
 * Uses the Montgomery ladder for constant-time scalar multiplication.
 *
 * This implementation prioritizes code size over speed, making it
 * suitable for resource-constrained microcontrollers.
 */

#include "x25519.h"
#include <string.h>

/*
 * Field element representation:
 * We use 64-bit limbs for better performance on Cortex-M33
 * Each element is in the range [0, 2^255-19)
 */
typedef int64_t gf[16];

static const gf GF0 = {0};
static const gf GF1 = {1};

/* Constant a24 = (A-2)/4 = 121665 for curve25519 Montgomery form */
static const gf GF121665 = {0xDB41, 1};

/*
 * Field arithmetic for curve25519
 * These are the same operations used in Ed25519, operating on GF(2^255-19)
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

/*
 * X25519 Montgomery ladder
 *
 * Computes scalar * point on Curve25519 using the Montgomery ladder.
 * This is constant-time with respect to the scalar.
 */
static void crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
    uint8_t z[32];
    gf x;
    gf a, b, c, d, e, f;
    int64_t r;

    /* Clamp scalar per RFC 7748 */
    for (int i = 0; i < 32; i++) z[i] = n[i];
    z[0] &= 248;      /* Clear bits 0, 1, 2 */
    z[31] &= 127;     /* Clear bit 255 */
    z[31] |= 64;      /* Set bit 254 */

    unpack25519(x, p);

    /* Initialize: a = 1, b = x, c = 0, d = 1 */
    set25519(a, GF1);
    set25519(b, x);
    set25519(c, GF0);
    set25519(d, GF1);

    /* Montgomery ladder */
    for (int i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);

        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, GF121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);

        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
    }

    /* Compute result: a/c */
    inv25519(c, c);
    M(a, a, c);
    pack25519(q, a);
}

/*
 * The X25519 base point (u=9)
 */
static const uint8_t BASEPOINT[32] = {9};

/*
 * Public API
 */

int x25519_init(void)
{
    return 0;
}

void x25519_public_key(uint8_t public_key[X25519_PUBLIC_KEY_SIZE],
                       const uint8_t secret_key[X25519_SECRET_KEY_SIZE])
{
    crypto_scalarmult(public_key, secret_key, BASEPOINT);
}

int x25519_shared_secret(uint8_t shared_secret[X25519_SHARED_SECRET_SIZE],
                         const uint8_t secret_key[X25519_SECRET_KEY_SIZE],
                         const uint8_t peer_public_key[X25519_PUBLIC_KEY_SIZE])
{
    uint8_t zero[32] = {0};

    crypto_scalarmult(shared_secret, secret_key, peer_public_key);

    /* Check for low-order points (shared secret would be all zeros) */
    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= shared_secret[i] ^ zero[i];

    if (diff == 0)
        return -1;

    return 0;
}

void x25519_scalarmult(uint8_t result[X25519_KEY_SIZE],
                       const uint8_t scalar[X25519_KEY_SIZE],
                       const uint8_t point[X25519_KEY_SIZE])
{
    crypto_scalarmult(result, scalar, point);
}

void x25519_keypair(uint8_t public_key[X25519_PUBLIC_KEY_SIZE],
                    const uint8_t secret_key[X25519_SECRET_KEY_SIZE])
{
    x25519_public_key(public_key, secret_key);
}

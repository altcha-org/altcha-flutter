// AltchaPbkdf2Bridge.mm
//
// PBKDF2-HMAC-SHA256/384/512.
//
// SHA-256 tiers (chosen at compile time):
//   1. ARM SHA-2 crypto extensions — all arm64 Apple devices/chips
//   2. Scalar C++ fallback — x86_64 (Intel Mac / iOS Simulator on Intel)
//
// SHA-384 and SHA-512 always use scalar C++ (ARM SHA-512 extensions require
// ARMv8.2, which is not universally available).
//
// HMAC ipad/opad states are precomputed once per PBKDF2 call, saving 2 SHA
// compressions per PBKDF2 internal iteration (vs CommonCrypto's 4).

#import "AltchaPbkdf2Bridge.h"
#include <cstring>
#include <cstdint>
#include <atomic>
#include <time.h>

// ---------------------------------------------------------------------------
// CPU feature detection — compile-time on Apple (no getauxval)
// ---------------------------------------------------------------------------

// ARM SHA-2 detection — compile-time only, resolved entirely by the preprocessor.

// ---------------------------------------------------------------------------
// Portable helpers
// ---------------------------------------------------------------------------

[[maybe_unused]] static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static inline uint32_t be32(const uint8_t* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3];
}
static inline uint64_t be64(const uint8_t* p) { return ((uint64_t)be32(p)<<32)|be32(p+4); }
static inline void put_be32(uint8_t* p, uint32_t v) { p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v; }
static inline void put_be64(uint8_t* p, uint64_t v) { put_be32(p,(uint32_t)(v>>32));put_be32(p+4,(uint32_t)v); }

// ---------------------------------------------------------------------------
// SHA-256 constants
// ---------------------------------------------------------------------------

static const uint32_t __attribute__((aligned(16))) K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

// ---------------------------------------------------------------------------
// SHA-256: ARM hardware path
// ---------------------------------------------------------------------------

#ifdef __aarch64__
#include <arm_neon.h>

__attribute__((target("sha2")))
static void sha256_compress_hw(uint32_t h[8], const uint8_t blk[64]) {
    uint32x4_t ABCD = vld1q_u32(h),     EFGH = vld1q_u32(h + 4);
    uint32x4_t ABCD0 = ABCD,            EFGH0 = EFGH;
    uint32x4_t MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk)));
    uint32x4_t MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 16)));
    uint32x4_t MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 32)));
    uint32x4_t MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk + 48)));
    uint32x4_t TMP, TMP2;
#define SHA256_RNDS4(msg, ki) \
    TMP  = vaddq_u32(msg, vld1q_u32(K256 + (ki))); \
    TMP2 = vsha256hq_u32(ABCD, EFGH, TMP);          \
    EFGH = vsha256h2q_u32(EFGH, ABCD, TMP);          \
    ABCD = TMP2;
#define SHA256_SCH(m0, m1, m2, m3) \
    m0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);
    SHA256_RNDS4(MSG0, 0)
    SHA256_RNDS4(MSG1, 4)  SHA256_SCH(MSG0, MSG1, MSG2, MSG3)
    SHA256_RNDS4(MSG2, 8)  SHA256_SCH(MSG1, MSG2, MSG3, MSG0)
    SHA256_RNDS4(MSG3, 12) SHA256_SCH(MSG2, MSG3, MSG0, MSG1)
    SHA256_RNDS4(MSG0, 16) SHA256_SCH(MSG3, MSG0, MSG1, MSG2)
    SHA256_RNDS4(MSG1, 20) SHA256_SCH(MSG0, MSG1, MSG2, MSG3)
    SHA256_RNDS4(MSG2, 24) SHA256_SCH(MSG1, MSG2, MSG3, MSG0)
    SHA256_RNDS4(MSG3, 28) SHA256_SCH(MSG2, MSG3, MSG0, MSG1)
    SHA256_RNDS4(MSG0, 32) SHA256_SCH(MSG3, MSG0, MSG1, MSG2)
    SHA256_RNDS4(MSG1, 36) SHA256_SCH(MSG0, MSG1, MSG2, MSG3)
    SHA256_RNDS4(MSG2, 40) SHA256_SCH(MSG1, MSG2, MSG3, MSG0)
    SHA256_RNDS4(MSG3, 44) SHA256_SCH(MSG2, MSG3, MSG0, MSG1)
    SHA256_RNDS4(MSG0, 48) SHA256_SCH(MSG3, MSG0, MSG1, MSG2)
    SHA256_RNDS4(MSG1, 52)
    SHA256_RNDS4(MSG2, 56)
    SHA256_RNDS4(MSG3, 60)
#undef SHA256_RNDS4
#undef SHA256_SCH
    vst1q_u32(h,     vaddq_u32(ABCD, ABCD0));
    vst1q_u32(h + 4, vaddq_u32(EFGH, EFGH0));
}
#endif // __aarch64__

// ---------------------------------------------------------------------------
// SHA-256: scalar path (not compiled when the hardware path covers all cases)
// ---------------------------------------------------------------------------

#if !(defined(__aarch64__) && defined(__ARM_FEATURE_SHA2))
static void sha256_compress_scalar(uint32_t h[8], const uint8_t b[64]) {
    uint32_t w[64],a,b2,c2,d,e,f,g,hh,t1,t2;
    for (int i=0;i<16;i++) w[i]=be32(b+i*4);
    for (int i=16;i<64;i++) {
        uint32_t s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=h[0];b2=h[1];c2=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (int i=0;i<64;i++) {
        t1=hh+(rotr32(e,6)^rotr32(e,11)^rotr32(e,25))+((e&f)^(~e&g))+K256[i]+w[i];
        t2=(rotr32(a,2)^rotr32(a,13)^rotr32(a,22))+((a&b2)^(a&c2)^(b2&c2));
        hh=g;g=f;f=e;e=d+t1;d=c2;c2=b2;b2=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b2;h[2]+=c2;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}
#endif // !(defined(__aarch64__) && defined(__ARM_FEATURE_SHA2))

static inline void sha256_compress(uint32_t h[8], const uint8_t b[64]) {
#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)
    sha256_compress_hw(h, b);
#else
    sha256_compress_scalar(h, b);
#endif
}

// ---------------------------------------------------------------------------
// SHA-256 context
// ---------------------------------------------------------------------------

struct Sha256Ctx { uint32_t h[8]; uint8_t buf[64]; uint64_t len; uint32_t fill; };

static void sha256_init(Sha256Ctx* c) {
    c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;
    c->len=0;c->fill=0;
}
static void sha256_update(Sha256Ctx* c, const uint8_t* d, size_t n) {
    c->len+=n;
    while (n>0) {
        uint32_t sp=64-c->fill,tk=(uint32_t)(n<sp?n:sp);
        memcpy(c->buf+c->fill,d,tk);c->fill+=tk;d+=tk;n-=tk;
        if(c->fill==64){sha256_compress(c->h,c->buf);c->fill=0;}
    }
}
static void sha256_final(Sha256Ctx* c, uint8_t out[32]) {
    uint64_t bits=c->len*8;
    static const uint8_t zeros[64]={};
    uint8_t p=0x80; sha256_update(c,&p,1);
    uint32_t need=(c->fill<=56)?(56-c->fill):(120-c->fill);
    sha256_update(c,zeros,need);
    uint8_t lb[8]; put_be64(lb,bits); sha256_update(c,lb,8);
    for (int i=0;i<8;i++) put_be32(out+i*4,c->h[i]);
}

// ---------------------------------------------------------------------------
// SHA-512 / SHA-384 (scalar; both share the same compression function)
// ---------------------------------------------------------------------------

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL,
};

struct Sha512Ctx { uint64_t h[8]; uint8_t buf[128]; uint64_t len; uint32_t fill; };

static void sha512_compress(uint64_t h[8], const uint8_t b[128]) {
    uint64_t w[80],a,b2,c2,d,e,f,g,hh,t1,t2;
    for (int i=0;i<16;i++) w[i]=be64(b+i*8);
    for (int i=16;i<80;i++) {
        uint64_t s0=rotr64(w[i-15],1)^rotr64(w[i-15],8)^(w[i-15]>>7);
        uint64_t s1=rotr64(w[i-2],19)^rotr64(w[i-2],61)^(w[i-2]>>6);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=h[0];b2=h[1];c2=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (int i=0;i<80;i++) {
        t1=hh+(rotr64(e,14)^rotr64(e,18)^rotr64(e,41))+((e&f)^(~e&g))+K512[i]+w[i];
        t2=(rotr64(a,28)^rotr64(a,34)^rotr64(a,39))+((a&b2)^(a&c2)^(b2&c2));
        hh=g;g=f;f=e;e=d+t1;d=c2;c2=b2;b2=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b2;h[2]+=c2;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void sha512_update(Sha512Ctx* c, const uint8_t* d, size_t n) {
    c->len+=n;
    while (n>0) {
        uint32_t sp=128-c->fill,tk=(uint32_t)(n<sp?n:sp);
        memcpy(c->buf+c->fill,d,tk);c->fill+=tk;d+=tk;n-=tk;
        if(c->fill==128){sha512_compress(c->h,c->buf);c->fill=0;}
    }
}

// SHA-512: init + final (64-byte output)
static void sha512_init(Sha512Ctx* c) {
    c->h[0]=0x6a09e667f3bcc908ULL;c->h[1]=0xbb67ae8584caa73bULL;
    c->h[2]=0x3c6ef372fe94f82bULL;c->h[3]=0xa54ff53a5f1d36f1ULL;
    c->h[4]=0x510e527fade682d1ULL;c->h[5]=0x9b05688c2b3e6c1fULL;
    c->h[6]=0x1f83d9abfb41bd6bULL;c->h[7]=0x5be0cd19137e2179ULL;
    c->len=0;c->fill=0;
}
static void sha512_final(Sha512Ctx* c, uint8_t out[64]) {
    uint64_t bits=c->len*8;
    uint8_t p=0x80; sha512_update(c,&p,1);
    uint8_t zero=0;
    while (c->fill!=112) sha512_update(c,&zero,1);
    uint8_t lb[16]={}; put_be64(lb+8,bits); sha512_update(c,lb,16);
    for (int i=0;i<8;i++) put_be64(out+i*8,c->h[i]);
}

// SHA-384: different IVs, same compression, 48-byte (6-word) truncated output
static void sha384_init(Sha512Ctx* c) {
    c->h[0]=0xcbbb9d5dc1059ed8ULL;c->h[1]=0x629a292a367cd507ULL;
    c->h[2]=0x9159015a3070dd17ULL;c->h[3]=0x152fecd8f70e5939ULL;
    c->h[4]=0x67332667ffc00b31ULL;c->h[5]=0x8eb44a8768581511ULL;
    c->h[6]=0xdb0c2e0d64f98fa7ULL;c->h[7]=0x47b5481dbefa4fa4ULL;
    c->len=0;c->fill=0;
}
static void sha384_final(Sha512Ctx* c, uint8_t out[48]) {
    uint64_t bits=c->len*8;
    uint8_t p=0x80; sha512_update(c,&p,1);
    uint8_t zero=0;
    while (c->fill!=112) sha512_update(c,&zero,1);
    uint8_t lb[16]={}; put_be64(lb+8,bits); sha512_update(c,lb,16);
    for (int i=0;i<6;i++) put_be64(out+i*8,c->h[i]); // first 48 bytes only
}

// ---------------------------------------------------------------------------
// HMAC with precomputed ipad/opad states
// ---------------------------------------------------------------------------

struct HmacSha256Ctx { Sha256Ctx ipad; Sha256Ctx opad; };
struct HmacSha512Ctx { Sha512Ctx ipad; Sha512Ctx opad; };
struct HmacSha384Ctx { Sha512Ctx ipad; Sha512Ctx opad; }; // SHA-384 reuses Sha512Ctx

static void hmac_sha256_init(HmacSha256Ctx* ctx, const uint8_t* k, size_t klen) {
    uint8_t key[64]={};
    if (klen>64){Sha256Ctx c;sha256_init(&c);sha256_update(&c,k,klen);sha256_final(&c,key);}
    else memcpy(key,k,klen);
    uint8_t ip[64],op[64];
    for (int i=0;i<64;i++){ip[i]=key[i]^0x36;op[i]=key[i]^0x5c;}
    sha256_init(&ctx->ipad);sha256_update(&ctx->ipad,ip,64);
    sha256_init(&ctx->opad);sha256_update(&ctx->opad,op,64);
}
static void hmac_sha256_compute(const HmacSha256Ctx* ctx,
                                const uint8_t* m, size_t mlen, uint8_t out[32]) {
    Sha256Ctx ic=ctx->ipad; sha256_update(&ic,m,mlen);
    uint8_t ih[32]; sha256_final(&ic,ih);
    Sha256Ctx oc=ctx->opad; sha256_update(&oc,ih,32);
    sha256_final(&oc,out);
}

static void hmac_sha512_init(HmacSha512Ctx* ctx, const uint8_t* k, size_t klen) {
    uint8_t key[128]={};
    if (klen>128){Sha512Ctx c;sha512_init(&c);sha512_update(&c,k,klen);sha512_final(&c,key);}
    else memcpy(key,k,klen);
    uint8_t ip[128],op[128];
    for (int i=0;i<128;i++){ip[i]=key[i]^0x36;op[i]=key[i]^0x5c;}
    sha512_init(&ctx->ipad);sha512_update(&ctx->ipad,ip,128);
    sha512_init(&ctx->opad);sha512_update(&ctx->opad,op,128);
}
static void hmac_sha512_compute(const HmacSha512Ctx* ctx,
                                const uint8_t* m, size_t mlen, uint8_t out[64]) {
    Sha512Ctx ic=ctx->ipad; sha512_update(&ic,m,mlen);
    uint8_t ih[64]; sha512_final(&ic,ih);
    Sha512Ctx oc=ctx->opad; sha512_update(&oc,ih,64);
    sha512_final(&oc,out);
}

static void hmac_sha384_init(HmacSha384Ctx* ctx, const uint8_t* k, size_t klen) {
    uint8_t key[128]={};
    if (klen>128) {
        // Hash the key with SHA-384 (48 bytes), rest of key stays zero
        Sha512Ctx c; sha384_init(&c); sha512_update(&c,k,klen); sha384_final(&c,key);
    } else {
        memcpy(key,k,klen);
    }
    uint8_t ip[128],op[128];
    for (int i=0;i<128;i++){ip[i]=key[i]^0x36;op[i]=key[i]^0x5c;}
    sha384_init(&ctx->ipad);sha512_update(&ctx->ipad,ip,128);
    sha384_init(&ctx->opad);sha512_update(&ctx->opad,op,128);
}
static void hmac_sha384_compute(const HmacSha384Ctx* ctx,
                                const uint8_t* m, size_t mlen, uint8_t out[48]) {
    Sha512Ctx ic=ctx->ipad; sha512_update(&ic,m,mlen);
    uint8_t ih[48]; sha384_final(&ic,ih);
    Sha512Ctx oc=ctx->opad; sha512_update(&oc,ih,48);
    sha384_final(&oc,out);
}

// ---------------------------------------------------------------------------
// PBKDF2
// ---------------------------------------------------------------------------

static void pbkdf2(const uint8_t* pw, size_t pwlen,
                   const uint8_t* salt, size_t slen,
                   int iterations, int keyLength, int hashId,
                   uint8_t* out) {
    const int dlen = (hashId==512) ? 64 : (hashId==384) ? 48 : 32;
    int numBlocks  = (keyLength+dlen-1)/dlen;

    HmacSha256Ctx hmac256; HmacSha512Ctx hmac512; HmacSha384Ctx hmac384;
    if      (hashId==512) hmac_sha512_init(&hmac512, pw, pwlen);
    else if (hashId==384) hmac_sha384_init(&hmac384, pw, pwlen);
    else                  hmac_sha256_init(&hmac256, pw, pwlen);

    // Stack buffer: salt (≤ 128 bytes in practice) + 4-byte block counter
    uint8_t saltBlock[256];
    memcpy(saltBlock, salt, slen);
    uint8_t u[64], f[64];

    for (int bn=1; bn<=numBlocks; bn++) {
        saltBlock[slen]  =(uint8_t)(bn>>24); saltBlock[slen+1]=(uint8_t)(bn>>16);
        saltBlock[slen+2]=(uint8_t)(bn>>8);  saltBlock[slen+3]=(uint8_t)(bn);

        if      (hashId==512) hmac_sha512_compute(&hmac512,saltBlock,slen+4,u);
        else if (hashId==384) hmac_sha384_compute(&hmac384,saltBlock,slen+4,u);
        else                  hmac_sha256_compute(&hmac256,saltBlock,slen+4,u);
        memcpy(f,u,dlen);

        for (int it=1; it<iterations; it++) {
            if      (hashId==512) hmac_sha512_compute(&hmac512,u,dlen,u);
            else if (hashId==384) hmac_sha384_compute(&hmac384,u,dlen,u);
            else                  hmac_sha256_compute(&hmac256,u,dlen,u);
            for (int i=0;i<dlen;i++) f[i]^=u[i];
        }

        int start=(bn-1)*dlen, cp=(dlen<keyLength-start)?dlen:keyLength-start;
        memcpy(out+start,f,cp);
    }
}

// ---------------------------------------------------------------------------
// Per-worker solve loop
// ---------------------------------------------------------------------------

static int altcha_pbkdf2_worker(
    const uint8_t* nonce, int nonceLen,
    const uint8_t* salt,  int saltLen,
    int cost, int keyLength, int hashId,
    const uint8_t* prefix, int prefixLen,
    int workerIdx, int workerCount,
    const std::atomic<bool>& done,
    int64_t deadlineMs,
    uint8_t* outKey)
{
    // Stack buffer for password = nonce || counter (nonce ≤ 16 bytes in practice)
    uint8_t password[64];
    memcpy(password, nonce, nonceLen);

    int counter = workerIdx;
    int iter    = 0;

    while (!done.load(std::memory_order_relaxed)) {
        // Check deadline every 16 iterations to amortise clock_gettime cost
        if ((iter & 0xF) == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            int64_t nowMs = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
            if (nowMs >= deadlineMs) return -1;
        }

        password[nonceLen]   = (uint8_t)(counter >> 24);
        password[nonceLen+1] = (uint8_t)(counter >> 16);
        password[nonceLen+2] = (uint8_t)(counter >>  8);
        password[nonceLen+3] = (uint8_t)(counter);

        pbkdf2(password, nonceLen + 4, salt, saltLen, cost, keyLength, hashId, outKey);

        bool matches = true;
        for (int i = 0; i < prefixLen; i++) {
            if (outKey[i] != prefix[i]) { matches = false; break; }
        }
        if (matches) return counter;

        counter += workerCount;
        iter++;
    }
    return -1;
}

// ---------------------------------------------------------------------------
// ObjC bridge
// ---------------------------------------------------------------------------

@implementation AltchaPbkdf2Bridge

+ (int)solveWithNonce:(NSData *)nonce
                 salt:(NSData *)salt
                 cost:(int)cost
            keyLength:(int)keyLength
               hashId:(int)hashId
               prefix:(NSData *)prefix
          workerCount:(int)workerCount
            timeoutMs:(long long)timeoutMs
               outKey:(NSMutableData *)outKey
{
    const int wc = MAX(1, MIN(workerCount, 16));

    // Deadline in monotonic milliseconds
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t deadlineMs = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + timeoutMs;

    // Shared state — written only by the winning worker
    std::atomic<bool> done{false};
    __block int       foundCounter = -1;
    uint8_t           foundKey[128] = {}; // ≥ max keyLength (64 bytes)
    uint8_t*          fkPtr = foundKey;

    const uint8_t* np  = (const uint8_t*)nonce.bytes;  int nl = (int)nonce.length;
    const uint8_t* sp  = (const uint8_t*)salt.bytes;   int sl = (int)salt.length;
    const uint8_t* pp  = prefix ? (const uint8_t*)prefix.bytes : nullptr;
    int             pl = prefix ? (int)prefix.length : 0;

    // These raw pointers are safe because dispatch_group_wait below keeps the
    // ObjC method stack frame alive until all blocks have finished.
    std::atomic<bool>* donePtr = &done;

    dispatch_group_t group = dispatch_group_create();
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0);

    for (int w = 0; w < wc; w++) {
        dispatch_group_async(group, queue, ^{
            uint8_t buf[128] = {};
            int c = altcha_pbkdf2_worker(np, nl, sp, sl,
                                         cost, keyLength, hashId,
                                         pp, pl,
                                         w, wc,
                                         *donePtr, deadlineMs,
                                         buf);
            if (c >= 0) {
                bool expected = false;
                if (donePtr->compare_exchange_strong(expected, true)) {
                    foundCounter = c;
                    memcpy(fkPtr, buf, keyLength);
                }
            }
        });
    }

    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);

    if (foundCounter >= 0) {
        memcpy(outKey.mutableBytes, foundKey, keyLength);
    }
    return foundCounter;
}

@end

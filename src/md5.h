// md5.h — 轻量 MD5 实现（RFC 1321，用于 HDB 特征匹配）
#pragma once

#include <string>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

namespace av { namespace md5 {

struct Context {
    uint32_t state[4];
    uint64_t count;
    uint8_t  buffer[64];
};

inline void init(Context& ctx) {
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
    ctx.count = 0;
}

inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

inline void transform(Context& ctx, const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const int S[64] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
                               5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
                               4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
                               6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
    uint32_t a = ctx.state[0], b = ctx.state[1], c = ctx.state[2], d = ctx.state[3];
    uint32_t M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8) |
               ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    for (int i = 0; i < 64; ++i) {
        uint32_t F; int g;
        if (i < 16)      { F = (b & c) | (~b & d); g = i; }
        else if (i < 32) { F = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { F = b ^ c ^ d;          g = (3*i + 5) % 16; }
        else             { F = c ^ (b | ~d);       g = (7*i) % 16; }
        uint32_t tmp = d;
        d = c; c = b;
        b = b + rol(a + F + K[i] + M[g], S[i]);
        a = tmp;
    }
    ctx.state[0] += a; ctx.state[1] += b; ctx.state[2] += c; ctx.state[3] += d;
}

inline void update(Context& ctx, const uint8_t* data, size_t len) {
    size_t idx = (size_t)(ctx.count / 8) % 64;
    ctx.count += len * 8;
    size_t part = 64 - idx;
    if (len >= part) {
        memcpy(ctx.buffer + idx, data, part);
        transform(ctx, ctx.buffer);
        for (size_t i = part; i + 63 < len; i += 64)
            transform(ctx, data + i);
        idx = 0;
    }
    memcpy(ctx.buffer + idx, data + len - (len % 64 ? len % 64 : (len >= part ? 0 : len)) ,
           len % 64 ? len % 64 : (len >= part ? 0 : len));
}

inline std::string final(Context& ctx) {
    static const uint8_t padding[64] = { 0x80 };
    uint8_t bits[8];
    for (int i = 0; i < 8; ++i) bits[i] = (uint8_t)(ctx.count >> (8 * i));
    size_t idx = (size_t)(ctx.count / 8) % 64;
    size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    update(ctx, padding, padLen);
    update(ctx, bits, 8);
    const char* hex = "0123456789abcdef";
    std::string out;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            uint8_t b = (uint8_t)(ctx.state[i] >> (8 * j));
            out += hex[b >> 4];
            out += hex[b & 0xF];
        }
    }
    return out;
}

inline std::string hashString(const std::string& data) {
    Context ctx; init(ctx);
    update(ctx, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    return final(ctx);
}

inline std::string hashFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    Context ctx; init(ctx);
    char buf[8192];
    while (f) {
        f.read(buf, sizeof(buf));
        size_t got = (size_t)f.gcount();
        if (got) update(ctx, reinterpret_cast<const uint8_t*>(buf), got);
    }
    return final(ctx);
}

}} // namespace av::md5

//
// Created by mvr on 05.01.22.
//

#include "utils.h"

uint32_t strTou32(const char *s) {
    uint32_t n {0};
    for (auto i=0; i<4; i++) {
        n <<= 8;
        n += (uint8_t)(s[i]);
    }
    return n;
}

std::string u32str(uint32_t n) {
    char s[4];
    for (auto i=3; i>=0; i--) {
        s[i] = (char)n;
        n >>= 8;
    }
    return std::string(s,4);
}

std::string u16str(uint16_t n) {
    char s[2];
    s[1] = (char)n;
    s[0] = (char)(n >> 8);
    return std::string(s,2);
}

std::string u8str(uint8_t n) {
    return std::string(1, (char)n);
}

void coef(const std::string &S, const uint8_t w, uint8_t *dest, const uint8_t num) {
    uint8_t k=0;
    const uint8_t mask = (1<<w) - 1;
    for (auto i=0; i<S.size(); i++) {
        uint8_t s = S[i];
        for (auto j=8-w; j>=0; j-=w) {
            dest[k] = (s >> j) & mask;
            k += 1;
            if (k == num) return;
        }
    }
    //return ((1<<w) - 1) & (S[(i*w) >> 3] >> (8 - (w * (i % (8 / w)) + w)));
}

std::string cksm(const std::string &S, const uint8_t w, const uint8_t n, const uint16_t ls) {
    const uint16_t m = (n*8)/w;
    uint8_t coefs[m];
    coef(S, w, coefs, m);
    uint16_t s = ((1<<w)-1) * m;
    for (auto i=0; i<m; i++) s -= coefs[i];
    return u16str(s << ls);
}

/*void cout_hex(const uint8_t *x, const size_t n) {
    for (auto i = 0; i < n; i++) std::cout << std::hex << std::setfill('0') << std::setw(2) << +x[i] << ' ';
    std::cout << std::endl;
}*/

INVALID::INVALID() : msg("INVALID") {}
INVALID::INVALID(std::string msg) : msg("INVALID: "+msg) {}
const char *INVALID::what() const noexcept {
    return msg.c_str();
}
FAILURE::FAILURE() : msg("FAILURE") {}
FAILURE::FAILURE(std::string msg) : msg("FAILURE: "+msg) {}
const char *FAILURE::what() const noexcept {
    return msg.c_str();
}


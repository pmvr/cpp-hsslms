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

uint8_t coef(const std::string S, const uint16_t i, const uint8_t w) {
    return ((1<<w) - 1) & (S[(i*w) >> 3] >> (8 - (w * (i % (8 / w)) + w)));
}

std::string cksm(const std::string S, const uint8_t w, const uint8_t n, const uint16_t ls) {
    uint16_t s {0};
    for (auto i=0; i<(n*8)/w; i++) {
        s += (1<<w) - 1 - coef(S,i,w);
    }
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


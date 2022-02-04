//
// Created by mvr on 05.01.22.
//

#ifndef LMS_HASH_BASED_SIGNATURES_UTILS_H
#define LMS_HASH_BASED_SIGNATURES_UTILS_H

#include <iostream>
#include <iomanip>

uint32_t strTou32(const char *s);
std::string u32str(uint32_t n);
std::string u16str(uint16_t n);
std::string u8str(uint8_t n);
void coef(const std::string &S, const uint8_t w, uint8_t *dest, const uint16_t num);
std::string cksm(const std::string &S, const uint8_t w, const uint8_t n, const uint16_t ls);

int32_t mod(int32_t a, int32_t b);

//void cout_hex(const uint8_t *x, const size_t n);

class INVALID : public std::exception {
private:
    const std::string msg;
public:
    INVALID();
    INVALID(std::string msg);
    const char* what() const noexcept;
};
class FAILURE : public std::exception {
private:
    const std::string msg;
public:
    FAILURE();
    FAILURE(std::string msg);
    const char* what() const noexcept;
};

#endif //LMS_HASH_BASED_SIGNATURES_UTILS_H

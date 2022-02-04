//
// Created by mvr on 05.01.22.
//

#ifndef LMS_HASH_BASED_SIGNATURES_LMOTS_H
#define LMS_HASH_BASED_SIGNATURES_LMOTS_H

#include <iostream>
#include <cstring>
#include "utils.h"
#include <openssl/rand.h>
#include <openssl/sha.h>

#define DIGEST_LENGTH SHA256_DIGEST_LENGTH

typedef struct {
    std::string typecode;
    uint8_t w;
    uint16_t p;
    uint8_t ls;
} LMOTS_ALGORITHM_TYPE;

//LMOTS Algorithm Types according to Table 1 in RFC 8554
extern const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W1;
extern const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W2;
extern const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W4;
extern const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W8;
extern const std::array<LMOTS_ALGORITHM_TYPE, 4> LMOTS_ALGORITHM_TYPES;

// domain-separation parameters
const std::string D_PBLC = u16str(0x8080);
const std::string D_MESG = u16str(0x8181);

LMOTS_ALGORITHM_TYPE findLmotsAlgType(const std::string &bstr);

class LM_OTS_Pub {
private:
    LMOTS_ALGORITHM_TYPE lmotsAlgorithmType;
    std::string I;
    std::string q;
    std::string K;
public:
    std::string pubkey;
    explicit LM_OTS_Pub(const std::string &pubkey);
    void algo4b(uint8_t Kc[DIGEST_LENGTH], const std::string &message, const std::string &signature);
    void verify(const std::string &message, const std::string &signature);
    std::string get_K();
};

class LM_OTS_Priv {
private:
    LMOTS_ALGORITHM_TYPE lmotsAlgorithmType;
    std::array<uint8_t, 16> I{};
    uint32_t q;
    uint8_t *x;
    bool used{};
public:
    LM_OTS_Priv(const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType, std::array<uint8_t, 16>& I, uint32_t q);
    LM_OTS_Priv(const std::string &bstr, uint32_t &index);
    ~LM_OTS_Priv();
    std::string sign(const std::string &message);
    LM_OTS_Pub gen_pub();
    std::string dump();
};


#endif //LMS_HASH_BASED_SIGNATURES_LMOTS_H

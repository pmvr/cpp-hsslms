//
// Created by mvr on 07.01.22.
//

#ifndef LMS_HASH_BASED_SIGNATURES_HSS_H
#define LMS_HASH_BASED_SIGNATURES_HSS_H

#include <iostream>
#include <vector>
#include "lms.h"
#include "lmots.h"

class HSS_Pub {
private:
    uint32_t L;
    std::string pub;
public:
    explicit HSS_Pub(const std::string &pubkey);
    void verify(const std::string &message, std::string signature);
    std::string get_pubkey();
};

class HSS_Priv {
private:
    const int NUM_THREADS;
    std::vector<LMS_ALGORITHM_TYPE> lmstypecodes;
    LMOTS_ALGORITHM_TYPE lmotsAlgorithmType;
    std::vector<LMS_Priv*> priv;
    std::vector<LMS_Pub> pub;
    std::vector<std::string> sig;
public:
    HSS_Priv(const std::vector<LMS_ALGORITHM_TYPE>& lmstypecodes, const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType, int NUM_THREADS);
    HSS_Priv(int NUM_THREADS, const std::string &bstr);
    ~HSS_Priv();
    std::string sign(const std::string &message);
    HSS_Pub gen_pub();
    std::string dump();
};

#endif //LMS_HASH_BASED_SIGNATURES_HSS_H

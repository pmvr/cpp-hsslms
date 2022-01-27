//
// Created by mvr on 19.01.22.
//

#ifndef LMS_HASH_BASED_SIGNATURES_PERSHSS_H
#define LMS_HASH_BASED_SIGNATURES_PERSHSS_H

#include <fstream>
#include "hss.h"
#include <openssl/evp.h>

class PersHSS_Priv : public HSS_Priv {
private:
    std::string filename;
    std::array<uint8_t, 16> salt;
    std::array<uint8_t, 32> key;
public:
    PersHSS_Priv(const std::vector<LMS_ALGORITHM_TYPE>& lmstypecodes,
                 const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType,
                 const std::string &filename,
                 const char* password,
                 int NUM_THREADS);
    PersHSS_Priv(const std::string &filename, const char *password, int NUM_THREADS, const std::string &bstr);
    void save();
    static PersHSS_Priv from_file(const std::string &filename, const char *password, int NUM_THREADS);
};

#endif //LMS_HASH_BASED_SIGNATURES_PERSHSS_H

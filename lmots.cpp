//
// Created by mvr on 05.01.22.
//
#include "lmots.h"

//LMOTS Algorithm Types according to Table 1 in RFC 8554
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W1 = {std::string("\000\000\000\001",4), 1, 265, 7};
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W2 = {std::string("\000\000\000\002",4), 2, 133, 6};
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W4 = {std::string("\000\000\000\003",4), 4, 67, 4};
const LMOTS_ALGORITHM_TYPE LMOTS_SHA256_N32_W8 = {std::string("\000\000\000\004",4), 8, 34, 0};

const std::array<LMOTS_ALGORITHM_TYPE, 4> LMOTS_ALGORITHM_TYPES = {LMOTS_SHA256_N32_W1, LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W8};

LMOTS_ALGORITHM_TYPE findLmotsAlgType(const std::string &bstr) {
    auto found = -1;
    for (auto i=0; i<LMOTS_ALGORITHM_TYPES.size(); i++) {
        if (LMOTS_ALGORITHM_TYPES.at(i).typecode == bstr) {
            found = i;
            break;
        }
    }
    if (found == -1) throw FAILURE("Wrong LMOTS_ALGORITHM_TYPE.");
    return LMOTS_ALGORITHM_TYPES.at(found);
}

LM_OTS_Priv::LM_OTS_Priv(const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType, std::array<uint8_t, 16>& I, uint32_t q)
        : lmotsAlgorithmType(lmotsAlgorithmType), I(I), q(q), used(false) {
    x = new uint8_t[DIGEST_LENGTH * lmotsAlgorithmType.p];
    if (RAND_priv_bytes(x, DIGEST_LENGTH*lmotsAlgorithmType.p) != 1) throw FAILURE("RAND_priv_bytes failure.");
}

LM_OTS_Priv::LM_OTS_Priv(const std::string &bstr, uint32_t &index) {
    if (bstr.length()-index < 4) throw FAILURE("Wrong LMOTS private key byte string.");
    lmotsAlgorithmType = findLmotsAlgType(bstr.substr(index, 4));
    index += 4;
    if (bstr.length()-index < I.size()+4+DIGEST_LENGTH * lmotsAlgorithmType.p) throw FAILURE("Wrong LMOTS private key byte string.");
    memcpy(I.data(), (uint8_t *)bstr.c_str()+index, I.size());
    index += I.size();
    q = strTou32(bstr.c_str()+index);
    index += 4;
    x = new uint8_t[DIGEST_LENGTH * lmotsAlgorithmType.p];
    memcpy(x, (uint8_t *)bstr.c_str()+index, DIGEST_LENGTH * lmotsAlgorithmType.p);
    index += DIGEST_LENGTH * lmotsAlgorithmType.p;
}

LM_OTS_Priv::~LM_OTS_Priv() {
    delete[] x;
}

std::string LM_OTS_Priv::sign(const std::string &message) {
    if (used) throw FAILURE("LMOTS private key has already been used for signature.");
    SHA256_CTX hash_ctx;
    std::string signature = lmotsAlgorithmType.typecode;
    signature.reserve(4+DIGEST_LENGTH*(lmotsAlgorithmType.p+1));
    auto *C = new uint8_t[DIGEST_LENGTH];
    if (RAND_priv_bytes(C, DIGEST_LENGTH) != 1) {
        delete[] C;
        throw FAILURE("RAND_priv_bytes failure.");
    }

    signature += std::string((char*)C, DIGEST_LENGTH);
    // Q
    uint8_t Q[DIGEST_LENGTH];
    SHA256_Init(&hash_ctx);
    SHA256_Update(&hash_ctx, I.data(), I.size());
    SHA256_Update(&hash_ctx, u32str(q).c_str(), 4);
    SHA256_Update(&hash_ctx, D_MESG.c_str(), D_MESG.size());
    SHA256_Update(&hash_ctx, C, DIGEST_LENGTH);
    SHA256_Update(&hash_ctx, message.c_str(), message.size());
    SHA256_Final(Q, &hash_ctx);
    std::string Qstr_chksm = std::string((char*)Q, sizeof(Q));
    Qstr_chksm += cksm(Qstr_chksm, lmotsAlgorithmType.w, DIGEST_LENGTH, lmotsAlgorithmType.ls);
    uint8_t tmp[DIGEST_LENGTH];
    uint8_t a[lmotsAlgorithmType.p];
    coef(Qstr_chksm, lmotsAlgorithmType.w, a, lmotsAlgorithmType.p);
    SHA256_CTX hash_ctx_pre;
    SHA256_Init(&hash_ctx_pre);
    SHA256_Update(&hash_ctx_pre, I.data(), I.size());
    SHA256_Update(&hash_ctx_pre, u32str(q).c_str(), 4);
    for (auto i=0; i<lmotsAlgorithmType.p; i++) {
        memcpy(tmp, x+i*DIGEST_LENGTH, DIGEST_LENGTH);
        for (auto j=0; j<a[i]; j++) {
            hash_ctx = hash_ctx_pre;
            SHA256_Update(&hash_ctx, u16str(i).c_str(), 2);
            SHA256_Update(&hash_ctx, u8str(j).c_str(), 1);
            SHA256_Update(&hash_ctx, tmp, DIGEST_LENGTH);
            SHA256_Final(tmp, &hash_ctx);
        }
        signature += std::string((char*)tmp, sizeof(tmp));
    }
    delete[] C;
    used = true;
    return signature;
}

LM_OTS_Pub LM_OTS_Priv::gen_pub() {
    SHA256_CTX K_ctx, tmp_ctx, tmp2_ctx;

    SHA256_Init(&K_ctx);
    SHA256_Update(&K_ctx, I.data(), I.size());
    SHA256_Update(&K_ctx, u32str(q).c_str(), 4);
    SHA256_Update(&K_ctx, D_PBLC.c_str(), D_PBLC.size());

    SHA256_Init(&tmp2_ctx);
    SHA256_Update(&tmp2_ctx, I.data(), I.size());
    SHA256_Update(&tmp2_ctx, u32str(q).c_str(), 4);
    uint8_t tmp[DIGEST_LENGTH];
    for (auto i=0; i<lmotsAlgorithmType.p; i++) {
        memcpy(tmp, x + i * DIGEST_LENGTH, DIGEST_LENGTH);
        for (auto j = 0; j < (1 << lmotsAlgorithmType.w) - 1; j++) {
            tmp_ctx = tmp2_ctx;
            SHA256_Update(&tmp_ctx, u16str(i).c_str(), 2);
            SHA256_Update(&tmp_ctx, u8str(j).c_str(), 1);
            SHA256_Update(&tmp_ctx, tmp, DIGEST_LENGTH);
            SHA256_Final(tmp, &tmp_ctx);
        }
        SHA256_Update(&K_ctx, tmp, DIGEST_LENGTH);
    }
    SHA256_Final(tmp, &K_ctx);
    return LM_OTS_Pub(lmotsAlgorithmType.typecode
            + std::string((char*)I.data(), I.size())
            + u32str(q)
            + std::string((char*)tmp, DIGEST_LENGTH));
}

std::string LM_OTS_Priv::dump() {
    return lmotsAlgorithmType.typecode
              + std::string((char*)I.data(), I.size())
              + u32str(q)
              + std::string((char*)x, DIGEST_LENGTH * lmotsAlgorithmType.p);
}

LM_OTS_Pub::LM_OTS_Pub(const std::string &pubkey) : pubkey(pubkey) {
    if (pubkey.size() < 4) throw INVALID("LMOTS public key is invalid.");
    lmotsAlgorithmType = findLmotsAlgType(pubkey.substr(0, 4));
    if (pubkey.size() != 24+DIGEST_LENGTH) throw INVALID("LMOTS public key is invalid.");
    I = pubkey.substr(4, 16);
    q = pubkey.substr(20,4);
    K = pubkey.substr(24, DIGEST_LENGTH);
}

std::string LM_OTS_Pub::get_K() {
    return K;
}

void LM_OTS_Pub::algo4b(uint8_t Kc[DIGEST_LENGTH], const std::string &message, const std::string &signature) {
    if (signature.size() < 4) throw INVALID("LMOTS signature is invalid.");
    if (pubkey.substr(0,4) != signature.substr(0,4)) throw INVALID("LMOTS signature is invalid.");
    if (signature.size() != 4 + DIGEST_LENGTH * (lmotsAlgorithmType.p+1)) throw INVALID("LMOTS signature is invalid.");
    std::string C = signature.substr(4,DIGEST_LENGTH);
    SHA256_CTX Q_ctx, tmp_ctx, hash_ctx_pre, Kc_ctx;
    uint8_t Q[DIGEST_LENGTH];
    SHA256_Init(&Q_ctx);
    SHA256_Update(&Q_ctx, I.data(), I.size());
    SHA256_Update(&Q_ctx, q.c_str(), q.size());
    SHA256_Update(&Q_ctx, D_MESG.c_str(), D_MESG.size());
    SHA256_Update(&Q_ctx, C.c_str(), C.size());
    SHA256_Update(&Q_ctx, message.c_str(), message.size());
    SHA256_Final(Q, &Q_ctx);
    std::string Qstr = std::string((char*)Q, DIGEST_LENGTH);
    SHA256_Init(&Kc_ctx);
    SHA256_Update(&Kc_ctx, I.data(), I.size());
    SHA256_Update(&Kc_ctx, q.c_str(), q.size());
    SHA256_Update(&Kc_ctx, D_PBLC.c_str(), D_PBLC.size());
    uint8_t tmp[DIGEST_LENGTH];
    uint8_t a[lmotsAlgorithmType.p];
    coef(Qstr + cksm(Qstr, lmotsAlgorithmType.w, DIGEST_LENGTH, lmotsAlgorithmType.ls), lmotsAlgorithmType.w, a, lmotsAlgorithmType.p);
    SHA256_Init(&hash_ctx_pre);
    SHA256_Update(&hash_ctx_pre, I.data(), I.size());
    SHA256_Update(&hash_ctx_pre, q.c_str(), 4);
    for (auto i=0; i<lmotsAlgorithmType.p; i++) {
        memcpy(tmp, signature.c_str()+4+(i+1)*DIGEST_LENGTH, DIGEST_LENGTH);
        for (auto j = a[i]; j < (1 << lmotsAlgorithmType.w) - 1; j++) {
            tmp_ctx = hash_ctx_pre;
            SHA256_Update(&tmp_ctx, u16str(i).c_str(), 2);
            SHA256_Update(&tmp_ctx, u8str(j).c_str(), 1);
            SHA256_Update(&tmp_ctx, tmp, DIGEST_LENGTH);
            SHA256_Final(tmp, &tmp_ctx);
        }
        SHA256_Update(&Kc_ctx, tmp, DIGEST_LENGTH);
    }
    SHA256_Final(Kc, &Kc_ctx);
}

void LM_OTS_Pub::verify(const std::string &message, const std::string &signature) {
    uint8_t Kc[DIGEST_LENGTH];
    algo4b(Kc, message, signature);
    uint8_t cor = 0;
    for (auto i=0; i<DIGEST_LENGTH; i++) {
        cor |= (Kc[i] ^ ((uint8_t )K.at(i)));
    }
    if (cor != 0) throw INVALID("LMOTS signature is invalid.");
}

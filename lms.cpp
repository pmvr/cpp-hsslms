//
// Created by mvr on 06.01.22.
//

#include "lms.h"
// LMS Algorithms Types according to Table 2 of RFC 8554
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H5 = {std::string("\000\000\000\005", 4), 5};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H10 = {std::string("\000\000\000\006", 4), 10};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H15 = {std::string("\000\000\000\007", 4), 15};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H20 = {std::string("\000\000\000\010", 4), 20};
const LMS_ALGORITHM_TYPE LMS_SHA256_M32_H25 = {std::string("\000\000\000\011", 4), 25};

const std::array<LMS_ALGORITHM_TYPE, 5> LMS_ALGORITHM_TYPES = {LMS_SHA256_M32_H5, LMS_SHA256_M32_H10, LMS_SHA256_M32_H15, LMS_SHA256_M32_H20, LMS_SHA256_M32_H25};

LMS_ALGORITHM_TYPE findLmsAlgType(const std::string &bstr) {
    auto found = -1;
    for (auto i = 0; i < LMS_ALGORITHM_TYPES.size(); i++) {
        if (LMS_ALGORITHM_TYPES.at(i).typecode == bstr) {
            found = i;
            break;
        }
    }
    if (found == -1) throw FAILURE("Wrong LMS_ALGORITHM_TYPE.");
    return LMS_ALGORITHM_TYPES.at(found);
}

void *LMS_Priv::compute_leafs(void *th_arg) {
    auto *arg = (struct th_args *)th_arg;
    const auto I = arg->prv->I;
    const auto h = arg->prv->typecode.h;
    const auto T = arg->prv->T;
    const auto OTS_PRIV= arg->prv->OTS_PRIV;
    const auto NUM_THREADS = arg->NUM_THREADS;
    SHA256_CTX T_ctx, tmp_ctx;
    SHA256_Init(&tmp_ctx);
    SHA256_Update(&tmp_ctx, I.data(), I.size());
    for (uint32_t r=(1 << h) + mod(arg->num - (1 << h),NUM_THREADS); r<(1 << (h+1)); r+=NUM_THREADS) {
        T_ctx = tmp_ctx;
        SHA256_Update(&T_ctx, u32str(r).c_str(), 4);
        SHA256_Update(&T_ctx, D_LEAF.c_str(), D_LEAF.size());
        SHA256_Update(&T_ctx, OTS_PRIV[r-(1 << h)]->gen_pub().get_K().c_str(), DIGEST_LENGTH);
        SHA256_Final(T+r*DIGEST_LENGTH, &T_ctx);
    }
    pthread_exit(nullptr);
}

void *LMS_Priv::compute_knots(void *th_arg) {
    auto *arg = (struct th_args *)th_arg;
    const auto I = arg->prv->I;
    const auto T = arg->prv->T;
    const auto NUM_THREADS = arg->NUM_THREADS;
    SHA256_CTX T_ctx, tmp_ctx;;
    SHA256_Init(&tmp_ctx);
    SHA256_Update(&tmp_ctx, I.data(), I.size());
    for (uint32_t r=(1 << arg->i) + mod(arg->num - (1 << arg->i),NUM_THREADS); r<(1 << (arg->i+1)); r+=NUM_THREADS) {
        T_ctx = tmp_ctx;
        SHA256_Update(&T_ctx, u32str(r).c_str(), 4);
        SHA256_Update(&T_ctx, D_INTR.c_str(), D_INTR.size());
        SHA256_Update(&T_ctx, T + 2 * r * DIGEST_LENGTH, DIGEST_LENGTH);
        SHA256_Update(&T_ctx, T + (2 * r + 1) * DIGEST_LENGTH, DIGEST_LENGTH);
        SHA256_Final(T + r * DIGEST_LENGTH, &T_ctx);
    }
    pthread_exit(nullptr);
}

void *LMS_Priv::compute_lmots_priv(void *th_arg) {
    auto *arg = (struct th_args *)th_arg;
    const auto lmotsAlgorithmType = arg->prv->lmotsAlgorithmType;
    auto I = arg->prv->I;
    const auto h = arg->prv->typecode.h;
    const auto OTS_PRIV = arg->prv->OTS_PRIV;
    const auto NUM_THREADS = arg->NUM_THREADS;
    for (uint32_t qi=arg->num; qi<(1 << h); qi+=NUM_THREADS) {
        OTS_PRIV[qi] = new LM_OTS_Priv(lmotsAlgorithmType, I, qi);
    }
    pthread_exit(nullptr);
}

LMS_Priv::LMS_Priv(const LMS_ALGORITHM_TYPE& typecode, const LMOTS_ALGORITHM_TYPE& lmotsAlgorithmType, const int NUM_THREADS)
        : typecode(typecode), lmotsAlgorithmType(lmotsAlgorithmType), I {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, NUM_THREADS(NUM_THREADS) {
    if (RAND_priv_bytes(I.data(), I.size()) != 1) throw FAILURE("RAND_priv_bytes failure.");
    pthread_t threads[NUM_THREADS];
    struct th_args args[NUM_THREADS];
    OTS_PRIV = new LM_OTS_Priv*[1 << typecode.h];
    for (auto k=0; k<NUM_THREADS; k++) {
        args[k].prv = this;
        args[k].num = k;
        args[k].NUM_THREADS = NUM_THREADS;
        if (pthread_create(&threads[k], nullptr, LMS_Priv::compute_lmots_priv, (void*)&args[k]) != 0) throw FAILURE("Thread creation.");
    }
    for (auto k=0; k<NUM_THREADS; k++) {
        if (pthread_join(threads[k], nullptr) != 0) throw FAILURE("Thread joining.");
    }
    q = 0;
    T = new uint8_t[DIGEST_LENGTH * (1 << (typecode.h + 1))];
    for (auto k=0; k<NUM_THREADS; k++) {
        if (pthread_create(&threads[k], nullptr, LMS_Priv::compute_leafs, (void*)&args[k]) != 0) throw FAILURE("Thread creation.");
    }
    for (auto k=0; k<NUM_THREADS; k++) {
        if (pthread_join(threads[k], nullptr) != 0) throw FAILURE("Thread joining.");
    }
    for (auto i=typecode.h-1; i>=0; i--) {
        for (auto k=0; k<NUM_THREADS; k++) {
            args[k].i = i;
            if (pthread_create(&threads[k], nullptr, LMS_Priv::compute_knots, (void*)&args[k]) != 0) throw FAILURE("Thread creation.");
        }
        for (auto k=0; k<NUM_THREADS; k++) {
            if (pthread_join(threads[k], nullptr) != 0) throw FAILURE("Thread joining.");
        }
    }
}

LMS_Priv::LMS_Priv(const std::string &bstr, uint32_t &index) : NUM_THREADS(1) {
    if (bstr.size()-index < 8) throw FAILURE("Wrong LMS private key byte string.");
    typecode = findLmsAlgType(bstr.substr(index,4));
    index += 4;
    lmotsAlgorithmType = findLmotsAlgType(bstr.substr(index,4));
    index += 4;
    if (bstr.size()-index < 4 + I.size() + DIGEST_LENGTH * (1 << (typecode.h + 1))) throw FAILURE("Wrong LMS private key byte string.");
    q = strTou32(bstr.c_str()+index);
    index += 4;
    memcpy(I.data(), (uint8_t *)bstr.c_str()+index, I.size());
    index += I.size();
    T = new uint8_t[DIGEST_LENGTH * (1 << (typecode.h + 1))];
    memcpy(T, (uint8_t *)bstr.c_str()+index, DIGEST_LENGTH * (1 << (typecode.h + 1)));
    index += DIGEST_LENGTH * (1 << (typecode.h + 1));
    OTS_PRIV = new LM_OTS_Priv*[1 << typecode.h];
    for (auto i=0; i<1 << typecode.h; i++) OTS_PRIV[i] = new LM_OTS_Priv(bstr, index);
}


//LMS_Priv::LMS_Priv(LMS_Priv &other) : typecode(other.typecode),
//                                      lmotsAlgorithmType(other.lmotsAlgorithmType),
//                                      I(other.I),
//                                      q(other.q) {
//    T = new uint8_t[DIGEST_LENGTH * (1 << (typecode.h + 1))];
//    memcpy(T, other.T, DIGEST_LENGTH * (1 << (typecode.h + 1)));
//}

LMS_Priv::~LMS_Priv() {
    for (uint32_t qi=0; qi<(1 << typecode.h); qi++) {
        delete OTS_PRIV[qi];
    }
    delete[] OTS_PRIV;
    delete[] T;
}

std::string LMS_Priv::sign(const std::string &message) {
    if (q >= (1 << typecode.h)) throw FAILURE("LMS private keys are exhausted.");
    std::string signature = u32str(q);
    signature += OTS_PRIV[q]->sign(message);
    signature += typecode.typecode;
    uint32_t r = (1 << typecode.h) + q;
    for (auto i=0; i<typecode.h; i++) {
        signature += std::string((char*)(T+(r ^ 1)*DIGEST_LENGTH), DIGEST_LENGTH);
        r >>= 1;
    }
    q += 1;
    return signature;
}

LMS_Pub LMS_Priv::gen_pub() {
    return LMS_Pub(typecode.typecode
    + lmotsAlgorithmType.typecode
    + std::string((char*)I.data(),I.size())
    + std::string((char*)(T+DIGEST_LENGTH), DIGEST_LENGTH));
}

uint32_t LMS_Priv::get_avail_signatures() const {
    return (1 << typecode.h) - q;
}

std::string LMS_Priv::dump() {
    auto ret = typecode.typecode
    + lmotsAlgorithmType.typecode
    + u32str(q)
    + std::string((char*)I.data(),I.size())
    + std::string((char*)T, DIGEST_LENGTH * (1 << (typecode.h + 1)));
    for (auto i=0; i<(1 << typecode.h); i++) ret += OTS_PRIV[i]->dump();
    return ret;
}


LMS_Pub::LMS_Pub(const std::string &pubkey) : pubkey(pubkey) {
    if (pubkey.size() < 8) throw INVALID("LMS public key is invalid.");
    lmsAlgorithmType = findLmsAlgType(pubkey.substr(0,4));
    lmotsAlgorithmType = findLmotsAlgType(pubkey.substr(4,4));
    if (pubkey.size() != 24+DIGEST_LENGTH) throw INVALID("LMS public key is invalid.");
    I = pubkey.substr(8, 16);
    T1 = pubkey.substr(24, DIGEST_LENGTH);
}

void LMS_Pub::verify(const std::string &message, const std::string &signature) {
    if (signature.size() < 8) throw INVALID("LMS signature is invalid.");
    uint32_t q = strTou32(signature.substr(0,4).c_str());
    if (lmotsAlgorithmType.typecode != signature.substr(4,4)) throw INVALID("LMS signature is invalid.");
    if (signature.size() < 12 + DIGEST_LENGTH*(lmotsAlgorithmType.p + 1)) throw INVALID("LMS signature is invalid.");
    std::string lmots_signature = signature.substr(4, 4+DIGEST_LENGTH*(lmotsAlgorithmType.p + 1));
    if (lmsAlgorithmType.typecode != signature.substr(8+DIGEST_LENGTH*(lmotsAlgorithmType.p + 1),4)) throw INVALID("LMS signature is invalid.");
    if ((q >= (1 << lmsAlgorithmType.h)) || (signature.size() != 12+DIGEST_LENGTH*(lmotsAlgorithmType.p+1)+DIGEST_LENGTH*lmsAlgorithmType.h)) throw INVALID("LMS signature is invalid.");
    LM_OTS_Pub OTS_PUB = LM_OTS_Pub(lmots_signature.substr(0,4) + I + u32str(q)  + std::string(DIGEST_LENGTH, 0));
    uint8_t Kc[DIGEST_LENGTH];
    OTS_PUB.algo4b(Kc, message, lmots_signature);
    uint32_t node_num = (1 << lmsAlgorithmType.h) + q;
    uint8_t tmp[DIGEST_LENGTH];
    SHA256_CTX tmp_ctx;
    SHA256_Init(&tmp_ctx);
    SHA256_Update(&tmp_ctx, I.data(), I.size());
    SHA256_Update(&tmp_ctx, u32str(node_num).c_str(), 4);
    SHA256_Update(&tmp_ctx, D_LEAF.c_str(), D_LEAF.size());
    SHA256_Update(&tmp_ctx, Kc, DIGEST_LENGTH);
    SHA256_Final(tmp, &tmp_ctx);
    uint8_t i = 0;
    while (node_num > 1) {
        SHA256_Init(&tmp_ctx);
        SHA256_Update(&tmp_ctx, I.data(), I.size());
        SHA256_Update(&tmp_ctx, u32str(node_num >> 1).c_str(), 4);
        SHA256_Update(&tmp_ctx, D_INTR.c_str(), D_INTR.size());
        if (node_num % 2 == 1) {
            SHA256_Update(&tmp_ctx, signature.substr(12+DIGEST_LENGTH*(lmotsAlgorithmType.p+1)+i*DIGEST_LENGTH,DIGEST_LENGTH).data(), DIGEST_LENGTH);
            SHA256_Update(&tmp_ctx, tmp, DIGEST_LENGTH);
        }
        else {
            SHA256_Update(&tmp_ctx, tmp, DIGEST_LENGTH);
            SHA256_Update(&tmp_ctx, signature.substr(12+DIGEST_LENGTH*(lmotsAlgorithmType.p+1)+i*DIGEST_LENGTH,DIGEST_LENGTH).data(), DIGEST_LENGTH);
        }
        SHA256_Final(tmp, &tmp_ctx);
        node_num >>= 1;
        i += 1;
    }
    uint8_t cor = 0;
    for (auto j=0; j<DIGEST_LENGTH; j++) {
        cor |= (tmp[j] ^ ((uint8_t )T1.at(j)));
    }
    if (cor != 0) throw INVALID("LMS signature is invalid.");
}

uint32_t LMS_Pub::len_pubkey() {
    return 24 + DIGEST_LENGTH;
}

uint32_t LMS_Pub::len_signature(const std::string &signature) {
    if (signature.size() < 4) throw INVALID("LMS signature is invalid.");
    try {
        LMOTS_ALGORITHM_TYPE _lmotsAlgorithmType = findLmotsAlgType(signature.substr(4, 4));
        if (signature.size() < 12 + DIGEST_LENGTH * (_lmotsAlgorithmType.p + 1)) throw INVALID("LMS signature is invalid.");
        LMS_ALGORITHM_TYPE _lmsAlgorithmType = findLmsAlgType(
                signature.substr(8 + DIGEST_LENGTH * (_lmotsAlgorithmType.p + 1), 4));
        if (signature.size() <
            12 + DIGEST_LENGTH * (_lmotsAlgorithmType.p + 1) + DIGEST_LENGTH * _lmsAlgorithmType.h)
            throw INVALID("LMS signature is invalid.");
        return 12 + DIGEST_LENGTH*(_lmotsAlgorithmType.p+1) + DIGEST_LENGTH * _lmsAlgorithmType.h;
    }
    catch (FAILURE &e) {
        throw INVALID("LMS signature is invalid.");
    }
}

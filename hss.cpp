//
// Created by mvr on 07.01.22.
//

#include "hss.h"

HSS_Priv::HSS_Priv(const std::vector<LMS_ALGORITHM_TYPE> &lmstypecodes,
                   const LMOTS_ALGORITHM_TYPE &lmotsAlgorithmType, const int NUM_THREADS) : lmstypecodes(lmstypecodes), lmotsAlgorithmType(lmotsAlgorithmType), NUM_THREADS(NUM_THREADS) {
    priv.emplace_back(new LMS_Priv(lmstypecodes[0], lmotsAlgorithmType, NUM_THREADS));
    pub.emplace_back(priv[0]->gen_pub());
    for (auto i=1; i<lmstypecodes.size(); i++) {
        priv.emplace_back(new LMS_Priv(lmstypecodes[i], lmotsAlgorithmType, NUM_THREADS));
        pub.emplace_back(priv[i]->gen_pub());
        sig.emplace_back(priv[i-1]->sign(pub[i].pubkey));
    }
}

HSS_Priv::HSS_Priv(const int NUM_THREADS, const std::string &bstr) : NUM_THREADS(NUM_THREADS) {
    if (bstr.size() < 4) throw FAILURE("Wrong HSS private key byte string.");
    auto L = strTou32(bstr.substr(0,4).c_str());
    uint32_t index=4;
    for (auto i=0; i<L; i++) {
        priv.emplace_back(new LMS_Priv(bstr, index));
        lmstypecodes.emplace_back(priv[i]->typecode);
        if (i == 0) lmotsAlgorithmType = priv[i]->lmotsAlgorithmType;
        else if (lmotsAlgorithmType.typecode != priv[i]->lmotsAlgorithmType.typecode) throw FAILURE("Wrong HSS private key byte string.");
    }
    auto len_pubkeys = LMS_Pub::len_pubkey();
    if (bstr.size()-index < len_pubkeys*L) throw FAILURE("Wrong HSS private key byte string.");
    for (auto i=0; i<L; i++, index += len_pubkeys) pub.emplace_back(LMS_Pub(bstr.substr(index, len_pubkeys)));
    for (auto i=0; i<L-1; i++) {
        try {
            auto len_sig = LMS_Pub::len_signature(bstr.substr(index, std::string::npos));
            if (bstr.size() - index < len_sig) throw FAILURE("Wrong HSS private key byte string.");
            sig.emplace_back(bstr.substr(index, len_sig));
            index += len_sig;
        }
        catch (std::exception &e) {
            throw FAILURE("Wrong HSS private key byte string.");
        }
    }
}


HSS_Priv::~HSS_Priv() {
    for (auto p : priv) delete p;
}

std::string HSS_Priv::sign(const std::string &message) {
    uint32_t L = lmstypecodes.size();
    uint32_t d=L;
    while (priv[d-1]->get_avail_signatures() == 0) {
        d -= 1;
        if (d== 0) throw FAILURE("HSS private keys are exhausted.");
    }
    for (auto i=d; i<L; i++) {
        delete priv[i];
        priv[i] = new LMS_Priv(lmstypecodes[i], lmotsAlgorithmType, NUM_THREADS);
        pub[i] = priv[i]->gen_pub();
        sig[i-1] = priv[i-1]->sign(pub[i].pubkey);
    }
    std::string signature = u32str(L-1);
    for (auto i=0; i<L-1; i++) {
        signature += sig[i];
        signature += pub[i+1].pubkey;
    }
    signature += priv[L-1]->sign(message);
    return signature;
}

HSS_Pub HSS_Priv::gen_pub() {
    return HSS_Pub(u32str(lmstypecodes.size()) + pub[0].pubkey);
}

std::string HSS_Priv::dump() {
    auto ret = u32str(lmstypecodes.size());  // L
    for (auto i=0; i<priv.size(); i++) ret += priv[i]->dump();
    for (auto i=0; i<pub.size(); i++) ret += pub[i].pubkey;
    for (auto i=0; i<sig.size(); i++) ret += sig[i];
    return ret;
}

HSS_Pub::HSS_Pub(const std::string &pubkey) {
    L = strTou32(pubkey.substr(0,4).c_str());
    pub = pubkey.substr(4, std::string::npos);
}

void HSS_Pub::verify(const std::string &message, std::string signature) {
    if (signature.size() < 4) throw INVALID("HSS signature is invalid.");
    uint32_t Nspk = strTou32(signature.substr(0,4).c_str());
    if (Nspk+1 != L) throw INVALID("HSS signature is invalid.");
    LMS_Pub key = LMS_Pub(pub);
    signature = signature.substr(4, std::string::npos);
    for (auto i=0; i<Nspk; i++) {
        uint32_t l = LMS_Pub::len_signature(signature);
        if (signature.size() < l) throw INVALID("HSS signature is invalid.");
        std::string lms_signature = signature.substr(0,l);
        signature = signature.substr(l, std::string::npos);
        l = LMS_Pub::len_pubkey();
        if (signature.size() < l) throw INVALID("HSS signature is invalid.");
        key.verify(signature.substr(0,l),lms_signature);
        key = LMS_Pub(signature.substr(0,l));
        signature = signature.substr(l,std::string::npos);
    }
    key.verify(message, signature);
}

std::string HSS_Pub::get_pubkey() {
    return u32str(L) + pub;
}
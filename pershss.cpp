//
// Created by mvr on 19.01.22.
//

#include "pershss.h"

int aes_gcm_encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *aad, int aad_len, uint8_t *key, uint8_t *iv, int iv_len, uint8_t *ciphertext, int &ciphertext_len, uint8_t *tag) {
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    EVP_CIPHER_CTX *ctx = nullptr;
    int len;

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) goto err;
    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) goto err;
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr)) goto err;
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) goto err;
    /* Provide any AAD data. This can be called zero or more times a required */
    if (aad_len > 0) if(1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len)) goto err;
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto err;
    ciphertext_len = len;
    /* Finalise the encryption. Normally ciphertext bytes may be written at this stage, but this does not occur in GCM mode */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto err;
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
    err:
        EVP_CIPHER_CTX_free(ctx);
        return 1;
}

int gcm_decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *aad, int aad_len, uint8_t *tag, uint8_t *key, uint8_t *iv, int iv_len, uint8_t *plaintext, int &plaintext_len) {
    // https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    EVP_CIPHER_CTX *ctx = nullptr;
    int len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) goto err;
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) goto err;
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr)) goto err;
    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) goto err;
    /* Provide any AAD data. This can be called zero or more times as required */
    if (aad_len > 0) if(!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len)) goto err;
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto err;
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) goto err;
    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a FAILURE() - the plaintext is not trustworthy. */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) goto err;
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
    err:
        EVP_CIPHER_CTX_free(ctx);
        return 1;
}


PersHSS_Priv::PersHSS_Priv(const std::vector<LMS_ALGORITHM_TYPE>& lmstypecodes, const LMOTS_ALGORITHM_TYPE &lmotsAlgorithmType,
                           const std::string &filename, const char* password, int NUM_THREADS)
        : HSS_Priv(lmstypecodes, lmotsAlgorithmType, NUM_THREADS),
          filename(filename) {
    RAND_priv_bytes(salt.data(), salt.size());
    PKCS5_PBKDF2_HMAC(password, -1, salt.data(), salt.size(), PBKDF2_ITER, EVP_sha256(), key.size(), key.data());
}

PersHSS_Priv::PersHSS_Priv(const std::string &filename, const char* password, int NUM_THREADS, const std::string &bstr)
        : HSS_Priv(NUM_THREADS, bstr), filename(filename) {
    RAND_priv_bytes(salt.data(), salt.size());
    PKCS5_PBKDF2_HMAC(password, -1, salt.data(), salt.size(), PBKDF2_ITER, EVP_sha256(), key.size(), key.data());
}

void PersHSS_Priv::save() {
    uint8_t IV[12];
    uint8_t tag[16];
    int ciphertext_len;

    RAND_priv_bytes(IV, sizeof(IV));
    std::string plaintext = this->dump();
    auto *ciphertext =  new uint8_t[plaintext.size()];
    if (aes_gcm_encrypt((uint8_t *)plaintext.c_str(), plaintext.size(), nullptr, 0, key.data(), IV, sizeof(IV), ciphertext, ciphertext_len, tag)) {
        delete[] ciphertext;
        throw FAILURE("Encryption Error.");
    }
    std::ofstream ofs;
    ofs.open(filename, std::ofstream::binary);
    ofs.write((char*)salt.data(), salt.size());
    ofs.write((char*)tag, sizeof(tag));
    ofs.write((char*)IV, sizeof(IV));
    ofs.write((char*)ciphertext, ciphertext_len);
    ofs.close();
    delete[] ciphertext;
}

PersHSS_Priv PersHSS_Priv::from_file(const std::string &filename, const char *password, const int NUM_THREADS) {
    uint8_t IV[12];
    uint8_t tag[16];
    uint8_t salt[16];
    uint8_t key[32];

    std::ifstream ifs;
    ifs.open(filename, std::ifstream::binary);
    if (!ifs) throw FAILURE(filename + " cannot be read.");
    // get length of file:
    ifs.seekg (0, std::ifstream::end);
    long length = ifs.tellg();
    ifs.seekg (0, std::ifstream::beg);
    ifs.read((char*)salt, sizeof(salt));
    if (!ifs) throw FAILURE(filename + " cannot be read.");
    PKCS5_PBKDF2_HMAC(password, -1, salt, sizeof(salt), PBKDF2_ITER, EVP_sha256(), sizeof(key), key);
    ifs.read((char*)tag, sizeof(tag));
    if (!ifs) throw FAILURE(filename + " cannot be read.");
    ifs.read((char*)IV, sizeof(IV));
    if (!ifs) throw FAILURE(filename + " cannot be read.");
    long ciphertext_len = length - sizeof(salt) - sizeof(tag) - sizeof(IV);
    if (ciphertext_len <= 0) throw FAILURE(filename + " cannot be read.");
    auto *ciphertext = new uint8_t[ciphertext_len];
    ifs.read((char*)ciphertext, ciphertext_len);
    if (!ifs) throw FAILURE(filename + " cannot be read.");
    ifs.close();
    auto *plaintext = new uint8_t[ciphertext_len];
    int plaintext_len;
    if (gcm_decrypt(ciphertext, ciphertext_len, nullptr, 0, tag, key, IV, sizeof(IV), plaintext, plaintext_len)) {
        delete[] ciphertext;
        delete[] plaintext;
        throw FAILURE("Wrong password.");
    }
    std::string dump = std::string((char*)plaintext, plaintext_len);
    delete[] ciphertext;
    delete[] plaintext;
    return PersHSS_Priv(filename, password, NUM_THREADS, dump);
}
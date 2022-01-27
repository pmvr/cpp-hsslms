//
// Created by mvr on 18.01.22.
//

#include "performancetest.h"

std::chrono::duration<double> perf_keygen(const std::vector<LMS_ALGORITHM_TYPE> &lmstypecodes, const LMOTS_ALGORITHM_TYPE &otstypecode, int NUM_THREADS) {
    auto start = std::chrono::steady_clock::now();
    HSS_Priv(lmstypecodes, otstypecode, NUM_THREADS);
    return std::chrono::steady_clock::now() - start;
}

void performance(int NUM_THREADS) {
    std::cout << "Using " << NUM_THREADS << " cores" << std::endl << std::endl;

    for (const auto& otstypecode : LMOTS_ALGORITHM_TYPES) {
        std::cout << "Performance of HSS-LMS with w=" << +otstypecode.w << std::endl;
        std::cout << "--------------------------------" << std::endl;
        std::cout << "  Performance of Key Generation:" << std::endl;
        std::cout << "           " << std::setw(10) << "Time[s]" << std::endl;

        auto duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H5}, otstypecode, NUM_THREADS);
        std::cout << "       H5: " << std::setw(10) << duration.count() << std::endl;
        duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H10}, otstypecode, NUM_THREADS);
        std::cout << "      H10: " << std::setw(10) << duration.count() << std::endl;
        duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H15}, otstypecode, NUM_THREADS);
        std::cout << "      H15: " << std::setw(10) << duration.count() << std::endl;
        duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H20}, otstypecode, NUM_THREADS);
        std::cout << "      H20: " << std::setw(10) << duration.count() << std::endl;
        duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H10, LMS_SHA256_M32_H10}, otstypecode, NUM_THREADS);
        std::cout << "  H10/H10: " << std::setw(10) << duration.count() << std::endl;
        duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H10, LMS_SHA256_M32_H15}, otstypecode, NUM_THREADS);
        std::cout << "  H10/H15: " << std::setw(10) << duration.count() << std::endl;
        duration = perf_keygen(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H15, LMS_SHA256_M32_H15}, otstypecode, NUM_THREADS);
        std::cout << "  H15/H15: " << std::setw(10) << duration.count() << std::endl;
    }

    for (const auto& otstypecode : LMOTS_ALGORITHM_TYPES) {
        auto sk = HSS_Priv(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H15}, otstypecode, NUM_THREADS);
        auto vk = sk.gen_pub();
        std::chrono::duration<double> duration_sign {0};
        std::chrono::duration<double> duration_verify {0};
        for (auto i=0; i<1000; i++) {
            auto start = std::chrono::steady_clock::now();
            auto signature = sk.sign("abc");
            duration_sign += std::chrono::steady_clock::now() - start;
            start = std::chrono::steady_clock::now();
            vk.verify("abc", signature);
            duration_verify += std::chrono::steady_clock::now() - start;
        }
        std::cout << "Performance of HSS-LMS with w=" << +otstypecode.w << std::endl;
        std::cout << "Signature Generation H15: " << std::setw(10) << duration_sign.count() << std::endl;
        std::cout << "Signature Verification H15: " << std::setw(10) << duration_verify.count() << std::endl;
    }


}


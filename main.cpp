#include <iostream>
#include <cstring>
#include "lmots.h"
#include "lms.h"
#include "hss.h"
#include "pershss.h"
#include "tests.h"
#include "performancetest.h"
#include <unistd.h>
#include <sys/sysinfo.h>

std::string readfile(std::string &filename) {
    std::ifstream ifs;
    ifs.open (filename, std::ifstream::binary);
    if (!ifs) throw FAILURE("Cannot open file.");
    // get length of file:
    ifs.seekg (0, std::ifstream::end);
    auto length = ifs.tellg();
    ifs.seekg (0, std::ifstream::beg);
    char *data = new char[length];
    ifs.read(data, length);
    if (!ifs) throw FAILURE("Cannot read file.");
    ifs.close();
    std::string ret = std::string(data, length);
    delete[] data;
    return ret;
}

void usage() {
    std::cout << "Hierarchical Signature System of Leighton-Micali Hash-Based Signatures according to RFC 8554\n"
                 "\n"
                 "Returns 0 if a command is executed without error and if a verification succeeded."
                 "\n"
                 "optional arguments:\n"
                 "  -h            show this help message and exit\n"
                 "\n"
                 "possible commands:\n"
                 "  -a {key-gen,sign,verify,test,performance}\n"
                 "\n"
                 "\n"
                 "command -a key-gen:\n"
                 "  generates a key pair"
                 "  arguments:\n"
                 "    -l [1234][56789]+  one LMOTS-typecode and at least one LMS-typecode\n"
                 "    -o filename  filename of private key, \".pub\" is appended to the filename of the pubklic key\n"
                 "    -p password  password to encrypt the private key\n"
                 "    -c number  number of cpu cores (1-#logical cores) for computation\n"
                 "\n"
                 "command -a pubkey-gen:\n"
                 "  generates the public key from a private key"
                 "  arguments:\n"
                 "    -k filename  filename of private key\n"
                 "    -p password  password to encrypt the private key\n"
                 "    -o filename  filename of the public key\n"
                 "\n"
                 "command -a sign:\n"
                 "  generates a signature"
                 "  arguments:\n"
                 "    -k filename  filename of private key\n"
                 "    -m filename  filename of message to be read and signed\n"
                 "    -o filename  filename of signature to be stored\n"
                 "    -p password  password to encrypt the private key\n"
                 "    -c number  number of cpu cores (1-#logical cores) for computation\n"
                 "\n"
                 "command -a verify:\n"
                 "  verifies a signature"
                 "  arguments:\n"
                 "    -k filename  filename of public key\n"
                 "    -m filename  filename of message to be read\n"
                 "    -s filename  filename of signature to be read\n"
                 "\n"
                 "command -a test:\n"
                 "  performs a number of tests."
                 "\n"
                 "command -a performance:\n"
                 "  does some performance measurements"
                 "  arguments:\n"
                 "    -c number  number of cpu cores (1-#logical cores) for computation\n"
                 "\n";
}

int action_test() {
    //test_mini();
    test_lm_ots();
    test_lms();
    test_hss();
    test_rfc8551();
    return 0;
}

int action_performance(int argc, char *argv[]) {
    int NUM_THREADS;
    switch(getopt(argc, argv, "c:")) {
        case 'c':
            NUM_THREADS = atoi(optarg);
            if ((NUM_THREADS <= 0) || (NUM_THREADS > get_nprocs())) {
                std::cout << "Number of thread shall be between 1 and the number of logical cores (here: " << get_nprocs() << ") in the system." << std::endl;
                return 1;
            }
            else performance(NUM_THREADS);
            break;
        case '?': //used for some unknown options
            printf("Unknown option: %c\n\n", optopt);
            usage();
            break;
        case 'h':
        default :
        case -1:
            usage();
            break;
    }
    return 0;
}

int action_key_gen(int argc, char *argv[]) {
    std::string typecode = std::string("\000\000\000\000", 4);
    std::vector<LMOTS_ALGORITHM_TYPE> lmotsAlgoType;
    std::vector<LMS_ALGORITHM_TYPE> lmsAlgoTypes;
    std::string filename;
    int NUM_THREADS = 0;
    char *password = nullptr;
    for (;;) {
        switch (getopt(argc, argv, "l:o:p:c:")) {
            case 'l':
                // scan algorithms types
                for (char *c=optarg; *c != 0; c++) {
                    typecode[3] = *c - '0';
                    try { lmsAlgoTypes.emplace_back(findLmsAlgType(typecode)); }
                    catch (FAILURE &e) {}
                    try { lmotsAlgoType.emplace_back(findLmotsAlgType(typecode)); }
                    catch (FAILURE &e) {}
                }
                continue;
            case 'o':
                filename = std::string(optarg);
                continue;
            case 'p':
                password = optarg;
                continue;
            case 'c':
                NUM_THREADS = atoi(optarg);
                continue;
            case 'h':
            case '?':
                usage();
                break;
            case -1:
                // verify if all parameters are set, i.e. valid
                if ((lmotsAlgoType.size() != 1) || (lmsAlgoTypes.empty()) || (filename.empty()) || (NUM_THREADS <= 0) || (NUM_THREADS > get_nprocs()) || (!password)) {
                    usage();
                    break;
                }
                try {
                    auto sk = PersHSS_Priv(lmsAlgoTypes, lmotsAlgoType[0], filename, password, NUM_THREADS);
                    sk.save();
                    auto pubkey = sk.gen_pub().get_pubkey();
                    std::ofstream ofs;
                    ofs.open(filename + ".pub", std::ofstream::out | std::ofstream::binary);
                    if (!ofs) throw FAILURE("Cannot write public key.");
                    ofs.write(pubkey.c_str(), pubkey.size());
                    if (!ofs) throw FAILURE("Cannot write public key.");
                    ofs.close();
                    return 0;
                }
                catch (FAILURE &e) {
                    std::cerr << "Key-Generation-Error" << std::endl;
                    std::cerr << e.what() << std::endl;
                    break;
                }
        }
        break;
    }
    return 1;
}

int action_pubkey_gen(int argc, char *argv[]) {
    std::string fn_key;
    char *password = nullptr;
    std::string fn_pubkey;
    const int NUM_THREADS = 1;

    for (;;) {
        switch (getopt(argc, argv, "k:p:o:")) {
            case 'k':
                fn_key = std::string(optarg);
                continue;
            case 'p':
                password = optarg;
                continue;
            case 'o':
                fn_pubkey = std::string(optarg);
                continue;
            case 'h':
            case '?':
                usage();
                break;
            case -1:
                if ((fn_key.empty()) || (fn_pubkey.empty()) || (!password)) {
                    usage();
                    break;
                }
                try {
                    auto sk = PersHSS_Priv::from_file(fn_key, password, NUM_THREADS);
                    auto pubkey = sk.gen_pub().get_pubkey();
                    std::ofstream ofs;
                    ofs.open(fn_pubkey, std::ofstream::out | std::ofstream::binary);
                    if (!ofs) throw FAILURE("Cannot write public key.");
                    ofs.write(pubkey.c_str(), pubkey.size());
                    if (!ofs) throw FAILURE("Cannot write public key.");
                    ofs.close();
                    return 0;
                }
                catch (FAILURE &e) {
                    std::cerr << "Signature-Generation-Error" << std::endl;
                    std::cerr << e.what() << std::endl;
                    break;
                }
        }
        break;
    }
    return 1;
}

int action_sign(int argc, char *argv[]) {
    std::string fn_key;
    char *password = nullptr;
    std::string fn_message;
    std::string fn_signature;
    int NUM_THREADS = 0;

    for (;;) {
        switch (getopt(argc, argv, "k:p:m:o:c:")) {
            case 'k':
                fn_key = std::string(optarg);
                continue;
            case 'p':
                password = optarg;
                continue;
            case 'm':
                fn_message = std::string(optarg);
                continue;
            case 'o':
                fn_signature = std::string(optarg);
                continue;
            case 'c':
                NUM_THREADS = atoi(optarg);
                continue;
            case 'h':
            case '?':
                usage();
                break;
            case -1:
                if ((fn_key.empty()) || (fn_signature.empty()) || (fn_signature.empty()) || (NUM_THREADS <= 0) || (NUM_THREADS > get_nprocs()) || (!password)) {
                    usage();
                    break;
                }
                try {
                    auto sk = PersHSS_Priv::from_file(fn_key, password, NUM_THREADS);
                    auto message = readfile(fn_message);
                    auto signature = sk.sign(message);
                    std::ofstream ofs;
                    ofs.open(fn_signature, std::ofstream::binary | std::ofstream::out);
                    if (!ofs) throw FAILURE("Cannot write signature.");
                    ofs.write(signature.c_str(), signature.size());
                    if (!ofs) throw FAILURE("Cannot write signature.");
                    ofs.close();
                    sk.save();
                    return 0;
                }
                catch (FAILURE &e) {
                    std::cerr << "Signature-Generation-Error" << std::endl;
                    std::cerr << e.what() << std::endl;
                    break;
                }
        }
        break;
    }
    return 1;
}

int action_verify(int argc, char *argv[]) {
    std::string fn_key;
    std::string fn_message;
    std::string fn_signature;

    for (;;) {
        switch (getopt(argc, argv, "k:m:s:")) {
            case 'k':
                fn_key = std::string(optarg);
                continue;
            case 'm':
                fn_message = std::string(optarg);
                continue;
            case 's':
                fn_signature = std::string(optarg);
                continue;
            case 'h':
            case '?':
                usage();
                break;
            case -1:
                if ((fn_key.empty()) || (fn_signature.empty()) || (fn_signature.empty())) {
                    usage();
                    break;
                }
                try {
                    auto vk = HSS_Pub(readfile(fn_key));
                    auto message = readfile(fn_message);
                    auto signature = readfile(fn_signature);
                    vk.verify(message, signature);
                    return 0;
                }
                catch (INVALID &e) {
                    std::cerr << "Signature is invalid." << std::endl;
                    break;
                }
                catch (FAILURE &e) {
                    std::cerr << "Signature-Verification-Error" << std::endl;
                    std::cerr << e.what() << std::endl;
                    break;
                }
        }
        break;
    }
    return 1;
}

int main(int argc, char *argv[]) {
//    HSS_Priv sk = HSS_Priv(std::vector<LMS_ALGORITHM_TYPE>{LMS_SHA256_M32_H15}, LMOTS_SHA256_N32_W8, 4);
//    exit(0);
    switch(getopt(argc, argv, "ha:")) {
        case 'a': //here an action
            if (strcmp(optarg, "test") == 0) return action_test();
            else if (strcmp(optarg, "performance") == 0) return action_performance(argc, argv);
            else if (strcmp(optarg, "key-gen") == 0) return action_key_gen(argc, argv);
            else if (strcmp(optarg, "pubkey-gen") == 0) return action_pubkey_gen(argc, argv);
            else if (strcmp(optarg, "sign") == 0) return action_sign(argc, argv);
            else if (strcmp(optarg, "verify") == 0) return action_verify(argc, argv);
            printf("Unknown command %s.\n\n", optarg);
            usage();
            break;
        case ':':
            printf("An option needs a value\n\n");
            usage();
            break;
        case '?': //used for some unknown options
            printf("Unknown option: %c\n\n", optopt);
            usage();
            break;
        case 'h':
        default:
        case -1:
            usage();
            break;
    }

    return 1;
}

#include <cuda_runtime.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>


const int KEY_LENGTH = 32;
const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


__global__ void generateRandomNumbers(unsigned char* d_results, int numKeys, int seed) {
    int idx = threadIdx.x + blockIdx.x * blockDim.x;
    if (idx < numKeys * KEY_LENGTH) {
        int keyIdx = idx / KEY_LENGTH;
        unsigned int state = seed + idx;
        state ^= (state << 13);
        state ^= (state >> 17);
        state ^= (state << 5);
        state += keyIdx;
        d_results[idx] = static_cast<unsigned char>(state % 256);
    }
}

class BitcoinKeyGenerator {
private:

    static std::string bytesToHex(const unsigned char* data, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; i++) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }


    static std::string base58Encode(const std::vector<unsigned char>& data) {
        BIGNUM* bn = BN_new();
        BIGNUM* bn_result = BN_new();
        BIGNUM* bn_58 = BN_new();
        std::string result;

        BN_bin2bn(data.data(), data.size(), bn);
        BN_set_word(bn_58, 58);

        while (BN_is_zero(bn) == 0) {
            BN_div(bn, bn_result, bn, bn_58, BN_CTX_new());
            int remainder = BN_get_word(bn_result);
            result = BASE58_CHARS[remainder] + result;
            BN_copy(bn, bn);
        }


        for (size_t i = 0; i < data.size() && data[i] == 0; i++) {
            result = '1' + result;
        }

        BN_free(bn);
        BN_free(bn_result);
        BN_free(bn_58);

        return result;
    }


    static std::string toWIF(const unsigned char* privateKey, size_t keyLength, bool compressed = true) {
        std::vector<unsigned char> wifData;
        

        wifData.push_back(0x80);
        

        wifData.insert(wifData.end(), privateKey, privateKey + keyLength);
        

        if (compressed) {
            wifData.push_back(0x01);
        }
        

        unsigned char hash1[SHA256_DIGEST_LENGTH];
        unsigned char hash2[SHA256_DIGEST_LENGTH];
        
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, wifData.data(), wifData.size());
        SHA256_Final(hash1, &sha256);
        
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, hash1, SHA256_DIGEST_LENGTH);
        SHA256_Final(hash2, &sha256);
        

        wifData.insert(wifData.end(), hash2, hash2 + 4);
        

        return base58Encode(wifData);
    }

public:
    static void generateKeysOnCPU(int numKeys) {
        std::cout << "Rozpoczynam generowanie na CPU..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < numKeys; i++) {
            EVP_PKEY_CTX *ctx = nullptr;
            EVP_PKEY *pkey = nullptr;
            BIGNUM *priv_key = nullptr;
            
            try {
                ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
                if (!ctx) continue;

                if (EVP_PKEY_keygen_init(ctx) <= 0 ||
                    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0 ||
                    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    continue;
                }

                if (EVP_PKEY_get_bn_param(pkey, "priv", &priv_key)) {
                    if (i < 3) { 
                        unsigned char priv_key_bin[32];
                        int bytes = BN_bn2bin(priv_key, priv_key_bin);
                        
                        std::cout << "CPU Klucz " << i + 1 << ":\n";
                        std::cout << "  HEX: " << bytesToHex(priv_key_bin, bytes) << std::endl;
                        std::cout << "  WIF: " << toWIF(priv_key_bin, bytes) << std::endl;
                    }
                    BN_free(priv_key);
                }

                EVP_PKEY_free(pkey);
                EVP_PKEY_CTX_free(ctx);
            } catch (const std::exception& e) {
                std::cerr << "Błąd generowania klucza CPU #" << i << ": " << e.what() << std::endl;
            }

            
            if (i % 1000 == 0) {
                std::cout << "Wygenerowano " << i << " kluczy..." << std::endl;
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        double milliseconds = duration.count() / 1000000.0;
        std::cout << "Czas generowania " << numKeys << " kluczy na CPU: " 
                  << milliseconds << " milisekund" << std::endl;
    }

    static void generateKeysOnGPU(int numKeys) {
        std::cout << "Rozpoczynam generowanie na GPU..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();

        try {
            std::cout << "Alokacja pamięci GPU..." << std::endl;
            unsigned char* d_random;
            size_t totalSize = numKeys * KEY_LENGTH;
            
            if (cudaMalloc(&d_random, totalSize) != cudaSuccess) {
                throw std::runtime_error("Błąd alokacji pamięci GPU");
            }

            std::cout << "Uruchamianie kernela CUDA..." << std::endl;
            int blockSize = 256;
            int numBlocks = (totalSize + blockSize - 1) / blockSize;
            generateRandomNumbers<<<numBlocks, blockSize>>>(d_random, numKeys, time(NULL));
            
            std::cout << "Kopiowanie wyników z GPU..." << std::endl;
            std::vector<unsigned char> h_random(totalSize);
            if (cudaMemcpy(h_random.data(), d_random, totalSize, cudaMemcpyDeviceToHost) != cudaSuccess) {
                cudaFree(d_random);
                throw std::runtime_error("Błąd kopiowania danych z GPU");
            }

            std::cout << "Przetwarzanie wygenerowanych kluczy..." << std::endl;
            for (int i = 0; i < std::min(3, numKeys); i++) {
                BIGNUM *priv_key = BN_bin2bn(&h_random[i * KEY_LENGTH], KEY_LENGTH, NULL);
                if (priv_key) {
                    std::cout << "GPU Klucz " << i + 1 << ":\n";
                    std::cout << "  HEX: " << bytesToHex(&h_random[i * KEY_LENGTH], KEY_LENGTH) << std::endl;
                    std::cout << "  WIF: " << toWIF(&h_random[i * KEY_LENGTH], KEY_LENGTH) << std::endl;
                    BN_free(priv_key);
                }
            }

            cudaFree(d_random);

        } catch (const std::exception& e) {
            std::cerr << "Błąd podczas generowania kluczy GPU: " << e.what() << std::endl;
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        double milliseconds = duration.count() / 1000000.0;
        std::cout << "Czas generowania " << numKeys << " kluczy na GPU: " 
                  << milliseconds << " milisekund" << std::endl;
    }
};

int main() {
    const int NUM_KEYS = 10000;
    
    std::cout << "Generowanie " << NUM_KEYS << " kluczy Bitcoin - porównanie CPU vs GPU\n" << std::endl;
    
    std::cout << "=== Test CPU ===\n" << std::endl;
    BitcoinKeyGenerator::generateKeysOnCPU(NUM_KEYS);
    
    std::cout << "\n=== Test GPU ===\n" << std::endl;
    BitcoinKeyGenerator::generateKeysOnGPU(NUM_KEYS);
    
    return 0;
}
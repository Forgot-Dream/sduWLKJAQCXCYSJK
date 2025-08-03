#ifndef SM4_H
#define SM4_H

#include <cstdint>
#include <array>
#include <vector>
#include <memory>
#include <cstring>

#ifdef __x86_64__
#include <immintrin.h>
#include <cpuid.h>
#endif

namespace SM4 {

// SM4常量定义
constexpr size_t BLOCK_SIZE = 16;
constexpr size_t KEY_SIZE = 16;
constexpr size_t ROUNDS = 32;

// S-box查找表
extern const uint8_t SBOX[256];
extern const uint8_t INV_SBOX[256];

// 系统参数FK
extern const uint32_t FK[4];

// 固定参数CK
extern const uint32_t CK[32];

// 基本工具函数
uint32_t leftRotate(uint32_t value, int bits);
uint8_t sbox(uint8_t input);
uint8_t invSbox(uint8_t input);
uint32_t linearTransform(uint32_t input);
uint32_t linearTransformPrime(uint32_t input);

// 基本SM4实现类
class Basic {
private:
    std::array<uint32_t, 32> roundKeys;
    
    uint32_t feistelFunction(uint32_t input);
    void keyExpansion(const uint8_t* key);
    
public:
    Basic() = default;
    ~Basic();
    
    void setKey(const uint8_t* key);
    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void decrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    
    // 清理敏感数据
    void clear();
};

// T-table优化实现类
class TTable {
private:
    std::array<uint32_t, 32> roundKeys;
    static std::array<uint32_t, 256> T0, T1, T2, T3;
    static bool tablesInitialized;
    
    static void initializeTables();
    uint32_t feistelFunction(uint32_t input);
    void keyExpansion(const uint8_t* key);
    
public:
    TTable();
    ~TTable();
    
    void setKey(const uint8_t* key);
    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void decrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    void clear();
};

#ifdef __x86_64__
// AESNI优化实现类
class AESNI {
private:
    std::array<uint32_t, 32> roundKeys;
    static bool aesniSupported;
    
    static bool checkAESNISupport();
    __m128i feistelFunctionSIMD(__m128i input);
    void keyExpansion(const uint8_t* key);
    
public:
    AESNI();
    ~AESNI();
    
    bool isSupported() const { return aesniSupported; }
    void setKey(const uint8_t* key);
    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void decrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    void clear();
};

// 现代指令集优化实现类
class ModernISA {
private:
    std::array<uint32_t, 32> roundKeys;
    static bool avxSupported;
    static bool avx2Supported;
    static bool avxVnniSupported;
    
    static bool checkModernISASupport();
    __m128i feistelFunctionAVX(__m128i input);
    __m128i feistelFunctionSSE(__m128i input);
    void keyExpansion(const uint8_t* key);
    
public:
    ModernISA();
    ~ModernISA();
    
    bool isSupported() const { return avxSupported; }
    void setKey(const uint8_t* key);
    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void decrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    
    // 批量处理方法 - SIMD真正发挥作用的地方
    void encryptBlocks(const uint8_t* plaintext, uint8_t* ciphertext, size_t blockCount);
    void decryptBlocks(const uint8_t* ciphertext, uint8_t* plaintext, size_t blockCount);
    
    void clear();
};
#endif

} // namespace SM4

// SM4-GCM工作模式实现
class SM4_GCM {
private:
    SM4::TTable sm4;
    std::array<uint64_t, 2> H;  // GCM子密钥
    std::vector<uint8_t> iv;
    std::vector<uint8_t> aad;   // 附加认证数据
    
    void generateSubkey();
    void ghash(const uint8_t* data, size_t len, uint8_t* hash);
    void gfmul(const uint8_t* x, const uint8_t* y, uint8_t* result);
    void incrementCounter(uint8_t* counter);
    
public:
    SM4_GCM() = default;
    ~SM4_GCM();
    
    void setKey(const uint8_t* key);
    void setIV(const uint8_t* iv, size_t ivLen);
    void setAAD(const uint8_t* aad, size_t aadLen);
    
    bool encrypt(const uint8_t* plaintext, size_t ptLen, 
                uint8_t* ciphertext, uint8_t* tag, size_t tagLen);
    bool decrypt(const uint8_t* ciphertext, size_t ctLen,
                const uint8_t* tag, size_t tagLen, uint8_t* plaintext);
    
    void clear();
};

// 性能测试工具
class PerformanceTest {
public:
    static void benchmarkBasic();
    static void benchmarkTTable();
    #ifdef __x86_64__
    static void benchmarkAESNI();
    static void benchmarkModernISA();
    #endif
    static void benchmarkGCM();
    static void runAllBenchmarks();
};

#endif // SM4_H

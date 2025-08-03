#include "sm4.h"
#include <algorithm>

#ifdef __x86_64__

namespace SM4 {

// 静态成员初始化
bool AESNI::aesniSupported = AESNI::checkAESNISupport();

bool AESNI::checkAESNISupport() {
    uint32_t eax, ebx, ecx, edx;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    return (ecx & bit_AES) != 0;
}

AESNI::AESNI() {
    // 如果不支持AESNI，构造函数仍然成功，但isSupported()会返回false
}

AESNI::~AESNI() {
    clear();
}

void AESNI::clear() {
    std::fill(roundKeys.begin(), roundKeys.end(), 0);
}

__m128i AESNI::feistelFunctionSIMD(__m128i input) {
    // 简化实现，直接使用标量操作
    uint32_t scalar_input = _mm_extract_epi32(input, 0);
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&scalar_input);
    
    bytes[0] = sbox(bytes[0]);
    bytes[1] = sbox(bytes[1]);
    bytes[2] = sbox(bytes[2]);
    bytes[3] = sbox(bytes[3]);
    
    uint32_t result = linearTransform(scalar_input);
    return _mm_set1_epi32(result);
}

void AESNI::keyExpansion(const uint8_t* key) {
    uint32_t K[4];
    
    // 将16字节密钥转换为4个32位字
    for (int i = 0; i < 4; i++) {
        K[i] = (static_cast<uint32_t>(key[4*i]) << 24) |
               (static_cast<uint32_t>(key[4*i+1]) << 16) |
               (static_cast<uint32_t>(key[4*i+2]) << 8) |
               static_cast<uint32_t>(key[4*i+3]);
    }
    
    // 与FK异或
    for (int i = 0; i < 4; i++) {
        K[i] ^= FK[i];
    }
    
    // 生成轮密钥
    for (int i = 0; i < 32; i++) {
        uint32_t temp = K[1] ^ K[2] ^ K[3] ^ CK[i];
        
        // S-box替换
        uint8_t* bytes = reinterpret_cast<uint8_t*>(&temp);
        bytes[0] = sbox(bytes[0]);
        bytes[1] = sbox(bytes[1]);
        bytes[2] = sbox(bytes[2]);
        bytes[3] = sbox(bytes[3]);
        
        // L'变换
        temp = linearTransformPrime(temp);
        
        roundKeys[i] = K[0] ^ temp;
        
        // 更新K
        K[0] = K[1];
        K[1] = K[2];
        K[2] = K[3];
        K[3] = roundKeys[i];
    }
}

void AESNI::setKey(const uint8_t* key) {
    keyExpansion(key);
}

void AESNI::encrypt(const uint8_t* plaintext, uint8_t* ciphertext) {
    uint32_t X[4];
    
    // 将16字节明文转换为4个32位字
    for (int i = 0; i < 4; i++) {
        X[i] = (static_cast<uint32_t>(plaintext[4*i]) << 24) |
               (static_cast<uint32_t>(plaintext[4*i+1]) << 16) |
               (static_cast<uint32_t>(plaintext[4*i+2]) << 8) |
               static_cast<uint32_t>(plaintext[4*i+3]);
    }
    
    // 32轮加密
    for (int i = 0; i < 32; i++) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ roundKeys[i];
        
        // 直接使用标量实现以确保正确性
        uint8_t* bytes = reinterpret_cast<uint8_t*>(&temp);
        bytes[0] = sbox(bytes[0]);
        bytes[1] = sbox(bytes[1]);
        bytes[2] = sbox(bytes[2]);
        bytes[3] = sbox(bytes[3]);
        temp = linearTransform(temp);
        
        uint32_t newX = X[0] ^ temp;
        
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = newX;
    }
    
    // 反序变换
    uint32_t Y[4] = {X[3], X[2], X[1], X[0]};
    
    // 将4个32位字转换为16字节密文
    for (int i = 0; i < 4; i++) {
        ciphertext[4*i] = static_cast<uint8_t>(Y[i] >> 24);
        ciphertext[4*i+1] = static_cast<uint8_t>(Y[i] >> 16);
        ciphertext[4*i+2] = static_cast<uint8_t>(Y[i] >> 8);
        ciphertext[4*i+3] = static_cast<uint8_t>(Y[i]);
    }
}

void AESNI::decrypt(const uint8_t* ciphertext, uint8_t* plaintext) {
    uint32_t X[4];
    
    // 将16字节密文转换为4个32位字
    for (int i = 0; i < 4; i++) {
        X[i] = (static_cast<uint32_t>(ciphertext[4*i]) << 24) |
               (static_cast<uint32_t>(ciphertext[4*i+1]) << 16) |
               (static_cast<uint32_t>(ciphertext[4*i+2]) << 8) |
               static_cast<uint32_t>(ciphertext[4*i+3]);
    }
    
    // 32轮解密（使用逆序轮密钥）
    for (int i = 31; i >= 0; i--) {
        uint32_t temp = X[1] ^ X[2] ^ X[3] ^ roundKeys[i];
        
        // 直接使用标量实现以确保正确性
        uint8_t* bytes = reinterpret_cast<uint8_t*>(&temp);
        bytes[0] = sbox(bytes[0]);
        bytes[1] = sbox(bytes[1]);
        bytes[2] = sbox(bytes[2]);
        bytes[3] = sbox(bytes[3]);
        temp = linearTransform(temp);
        
        uint32_t newX = X[0] ^ temp;
        
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = newX;
    }
    
    // 反序变换
    uint32_t Y[4] = {X[3], X[2], X[1], X[0]};
    
    // 将4个32位字转换为16字节明文
    for (int i = 0; i < 4; i++) {
        plaintext[4*i] = static_cast<uint8_t>(Y[i] >> 24);
        plaintext[4*i+1] = static_cast<uint8_t>(Y[i] >> 16);
        plaintext[4*i+2] = static_cast<uint8_t>(Y[i] >> 8);
        plaintext[4*i+3] = static_cast<uint8_t>(Y[i]);
    }
}

} // namespace SM4

#endif // __x86_64__

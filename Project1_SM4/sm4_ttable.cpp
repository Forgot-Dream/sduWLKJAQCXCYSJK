#include "sm4.h"
#include <algorithm>

namespace SM4 {

// 静态成员初始化
std::array<uint32_t, 256> TTable::T0;
std::array<uint32_t, 256> TTable::T1;
std::array<uint32_t, 256> TTable::T2;
std::array<uint32_t, 256> TTable::T3;
bool TTable::tablesInitialized = false;

void TTable::initializeTables() {
    if (tablesInitialized) return;
    
    for (int i = 0; i < 256; i++) {
        uint32_t temp = sbox(i);
        
        // T0[i] = L(S[i] || 0 || 0 || 0)
        T0[i] = linearTransform(temp << 24);
        
        // T1[i] = L(0 || S[i] || 0 || 0)
        T1[i] = linearTransform(temp << 16);
        
        // T2[i] = L(0 || 0 || S[i] || 0)
        T2[i] = linearTransform(temp << 8);
        
        // T3[i] = L(0 || 0 || 0 || S[i])
        T3[i] = linearTransform(temp);
    }
    
    tablesInitialized = true;
}

TTable::TTable() {
    initializeTables();
}

TTable::~TTable() {
    clear();
}

void TTable::clear() {
    std::fill(roundKeys.begin(), roundKeys.end(), 0);
}

uint32_t TTable::feistelFunction(uint32_t input) {
    uint8_t b0 = static_cast<uint8_t>(input >> 24);
    uint8_t b1 = static_cast<uint8_t>(input >> 16);
    uint8_t b2 = static_cast<uint8_t>(input >> 8);
    uint8_t b3 = static_cast<uint8_t>(input);
    
    return T0[b0] ^ T1[b1] ^ T2[b2] ^ T3[b3];
}

void TTable::keyExpansion(const uint8_t* key) {
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

void TTable::setKey(const uint8_t* key) {
    keyExpansion(key);
}

void TTable::encrypt(const uint8_t* plaintext, uint8_t* ciphertext) {
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
        temp = feistelFunction(temp);
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

void TTable::decrypt(const uint8_t* ciphertext, uint8_t* plaintext) {
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
        temp = feistelFunction(temp);
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

#include "sm4.h"
#include <algorithm>
#include <random>

// SM4-GCM工作模式实现

SM4_GCM::~SM4_GCM() {
    clear();
}

void SM4_GCM::clear() {
    sm4.clear();
    std::fill(H.begin(), H.end(), 0);
    std::fill(iv.begin(), iv.end(), 0);
    std::fill(aad.begin(), aad.end(), 0);
}

void SM4_GCM::setKey(const uint8_t* key) {
    sm4.setKey(key);
    generateSubkey();
}

void SM4_GCM::generateSubkey() {
    // 生成GCM子密钥H = E_K(0^128)
    uint8_t zero_block[16] = {0};
    uint8_t h_bytes[16];
    
    sm4.encrypt(zero_block, h_bytes);
    
    // 将字节序列转换为两个64位整数
    H[0] = 0;
    H[1] = 0;
    for (int i = 0; i < 8; i++) {
        H[0] = (H[0] << 8) | h_bytes[i];
        H[1] = (H[1] << 8) | h_bytes[i + 8];
    }
}

void SM4_GCM::setIV(const uint8_t* iv_data, size_t ivLen) {
    iv.clear();
    iv.resize(ivLen);
    std::copy(iv_data, iv_data + ivLen, iv.begin());
}

void SM4_GCM::setAAD(const uint8_t* aad_data, size_t aadLen) {
    aad.clear();
    aad.resize(aadLen);
    std::copy(aad_data, aad_data + aadLen, aad.begin());
}

void SM4_GCM::gfmul(const uint8_t* x, const uint8_t* y, uint8_t* result) {
    // GF(2^128)乘法实现
    uint8_t z[16] = {0};
    uint8_t v[16];
    std::copy(y, y + 16, v);
    
    for (int i = 0; i < 128; i++) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        
        if (x[byte_idx] & (1 << bit_idx)) {
            // z = z ⊕ v
            for (int j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        
        // v = v >> 1
        uint8_t carry = 0;
        for (int j = 0; j < 16; j++) {
            uint8_t new_carry = v[j] & 1;
            v[j] = (v[j] >> 1) | (carry << 7);
            carry = new_carry;
        }
        
        // 如果最低位为1，异或约简多项式
        if (carry) {
            v[0] ^= 0xE1; // 约简多项式的最高字节
        }
    }
    
    std::copy(z, z + 16, result);
}

void SM4_GCM::ghash(const uint8_t* data, size_t len, uint8_t* hash) {
    uint8_t y[16] = {0};
    uint8_t h_bytes[16];
    
    // 将H转换为字节数组
    for (int i = 0; i < 8; i++) {
        h_bytes[i] = static_cast<uint8_t>(H[0] >> (56 - 8 * i));
        h_bytes[i + 8] = static_cast<uint8_t>(H[1] >> (56 - 8 * i));
    }
    
    // 处理完整的16字节块
    size_t full_blocks = len / 16;
    for (size_t i = 0; i < full_blocks; i++) {
        // y = (y ⊕ X_i) • H
        for (int j = 0; j < 16; j++) {
            y[j] ^= data[i * 16 + j];
        }
        
        uint8_t temp[16];
        gfmul(y, h_bytes, temp);
        std::copy(temp, temp + 16, y);
    }
    
    // 处理剩余的不完整块
    size_t remaining = len % 16;
    if (remaining > 0) {
        uint8_t padded_block[16] = {0};
        std::copy(data + full_blocks * 16, data + len, padded_block);
        
        for (int j = 0; j < 16; j++) {
            y[j] ^= padded_block[j];
        }
        
        uint8_t temp[16];
        gfmul(y, h_bytes, temp);
        std::copy(temp, temp + 16, y);
    }
    
    std::copy(y, y + 16, hash);
}

void SM4_GCM::incrementCounter(uint8_t* counter) {
    // 递增计数器的最低32位
    uint32_t low = (static_cast<uint32_t>(counter[12]) << 24) |
                   (static_cast<uint32_t>(counter[13]) << 16) |
                   (static_cast<uint32_t>(counter[14]) << 8) |
                   static_cast<uint32_t>(counter[15]);
    
    low++;
    
    counter[12] = static_cast<uint8_t>(low >> 24);
    counter[13] = static_cast<uint8_t>(low >> 16);
    counter[14] = static_cast<uint8_t>(low >> 8);
    counter[15] = static_cast<uint8_t>(low);
}

bool SM4_GCM::encrypt(const uint8_t* plaintext, size_t ptLen, 
                     uint8_t* ciphertext, uint8_t* tag, size_t tagLen) {
    if (iv.empty()) {
        return false; // IV必须设置
    }
    
    // 初始化计数器
    uint8_t j0[16] = {0};
    if (iv.size() == 12) {
        // 如果IV长度为96位，直接使用并在末尾加上计数器1
        std::copy(iv.begin(), iv.end(), j0);
        j0[15] = 1;
    } else {
        // 否则使用GHASH处理IV
        ghash(iv.data(), iv.size(), j0);
    }
    
    // 生成认证标签的初始值
    uint8_t tag_mask[16];
    sm4.encrypt(j0, tag_mask);
    
    // CTR模式加密
    uint8_t counter[16];
    std::copy(j0, j0 + 16, counter);
    
    size_t full_blocks = ptLen / 16;
    size_t remaining = ptLen % 16;
    
    // 处理完整块
    for (size_t i = 0; i < full_blocks; i++) {
        incrementCounter(counter);
        uint8_t keystream[16];
        sm4.encrypt(counter, keystream);
        
        for (int j = 0; j < 16; j++) {
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
        }
    }
    
    // 处理剩余字节
    if (remaining > 0) {
        incrementCounter(counter);
        uint8_t keystream[16];
        sm4.encrypt(counter, keystream);
        
        for (size_t j = 0; j < remaining; j++) {
            ciphertext[full_blocks * 16 + j] = plaintext[full_blocks * 16 + j] ^ keystream[j];
        }
    }
    
    // 计算认证标签
    size_t total_len = aad.size() + ptLen;
    std::vector<uint8_t> auth_data(total_len + 16); // +16 for length encoding
    
    // 拷贝AAD
    if (!aad.empty()) {
        std::copy(aad.begin(), aad.end(), auth_data.begin());
    }
    
    // 拷贝密文
    std::copy(ciphertext, ciphertext + ptLen, auth_data.begin() + aad.size());
    
    // 添加长度编码
    uint64_t aad_len_bits = aad.size() * 8;
    uint64_t ct_len_bits = ptLen * 8;
    
    for (int i = 0; i < 8; i++) {
        auth_data[total_len + i] = static_cast<uint8_t>(aad_len_bits >> (56 - 8 * i));
        auth_data[total_len + 8 + i] = static_cast<uint8_t>(ct_len_bits >> (56 - 8 * i));
    }
    
    uint8_t auth_tag[16];
    ghash(auth_data.data(), auth_data.size(), auth_tag);
    
    // 与tag_mask异或得到最终标签
    size_t actual_tag_len = std::min(tagLen, size_t(16));
    for (size_t i = 0; i < actual_tag_len; i++) {
        tag[i] = auth_tag[i] ^ tag_mask[i];
    }
    
    return true;
}

bool SM4_GCM::decrypt(const uint8_t* ciphertext, size_t ctLen,
                     const uint8_t* tag, size_t tagLen, uint8_t* plaintext) {
    if (iv.empty()) {
        return false; // IV必须设置
    }
    
    // 初始化计数器
    uint8_t j0[16] = {0};
    if (iv.size() == 12) {
        std::copy(iv.begin(), iv.end(), j0);
        j0[15] = 1;
    } else {
        ghash(iv.data(), iv.size(), j0);
    }
    
    // 生成认证标签的初始值
    uint8_t tag_mask[16];
    sm4.encrypt(j0, tag_mask);
    
    // 验证认证标签
    size_t total_len = aad.size() + ctLen;
    std::vector<uint8_t> auth_data(total_len + 16);
    
    if (!aad.empty()) {
        std::copy(aad.begin(), aad.end(), auth_data.begin());
    }
    
    std::copy(ciphertext, ciphertext + ctLen, auth_data.begin() + aad.size());
    
    uint64_t aad_len_bits = aad.size() * 8;
    uint64_t ct_len_bits = ctLen * 8;
    
    for (int i = 0; i < 8; i++) {
        auth_data[total_len + i] = static_cast<uint8_t>(aad_len_bits >> (56 - 8 * i));
        auth_data[total_len + 8 + i] = static_cast<uint8_t>(ct_len_bits >> (56 - 8 * i));
    }
    
    uint8_t expected_tag[16];
    ghash(auth_data.data(), auth_data.size(), expected_tag);
    
    // 与tag_mask异或得到预期标签
    for (int i = 0; i < 16; i++) {
        expected_tag[i] ^= tag_mask[i];
    }
    
    // 验证标签
    size_t actual_tag_len = std::min(tagLen, size_t(16));
    for (size_t i = 0; i < actual_tag_len; i++) {
        if (expected_tag[i] != tag[i]) {
            return false; // 认证失败
        }
    }
    
    // CTR模式解密
    uint8_t counter[16];
    std::copy(j0, j0 + 16, counter);
    
    size_t full_blocks = ctLen / 16;
    size_t remaining = ctLen % 16;
    
    // 处理完整块
    for (size_t i = 0; i < full_blocks; i++) {
        incrementCounter(counter);
        uint8_t keystream[16];
        sm4.encrypt(counter, keystream);
        
        for (int j = 0; j < 16; j++) {
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
        }
    }
    
    // 处理剩余字节
    if (remaining > 0) {
        incrementCounter(counter);
        uint8_t keystream[16];
        sm4.encrypt(counter, keystream);
        
        for (size_t j = 0; j < remaining; j++) {
            plaintext[full_blocks * 16 + j] = ciphertext[full_blocks * 16 + j] ^ keystream[j];
        }
    }
    
    return true;
}

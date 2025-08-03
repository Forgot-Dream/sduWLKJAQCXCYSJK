#include "sm4.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <functional>

// 测试向量
const uint8_t test_key[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

const uint8_t test_plaintext[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
};

const uint8_t expected_ciphertext[16] = {
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
};

void printHex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(data[i]);
        if (i < len - 1) std::cout << " ";
    }
    std::cout << std::dec << std::endl;
}

bool testBasicSM4() {
    std::cout << "=== 测试基本SM4实现 ===" << std::endl;
    
    SM4::Basic sm4;
    sm4.setKey(test_key);
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    // 加密测试
    sm4.encrypt(test_plaintext, ciphertext);
    std::cout << "明文: ";
    printHex(test_plaintext, 16);
    std::cout << "密文: ";
    printHex(ciphertext, 16);
    std::cout << "期望: ";
    printHex(expected_ciphertext, 16);
    
    bool encrypt_ok = memcmp(ciphertext, expected_ciphertext, 16) == 0;
    std::cout << "加密测试: " << (encrypt_ok ? "通过" : "失败") << std::endl;
    
    // 解密测试
    sm4.decrypt(ciphertext, decrypted);
    std::cout << "解密: ";
    printHex(decrypted, 16);
    
    bool decrypt_ok = memcmp(decrypted, test_plaintext, 16) == 0;
    std::cout << "解密测试: " << (decrypt_ok ? "通过" : "失败") << std::endl;
    
    return encrypt_ok && decrypt_ok;
}

bool testTTableSM4() {
    std::cout << "\n=== 测试T-table优化SM4实现 ===" << std::endl;
    
    SM4::TTable sm4;
    sm4.setKey(test_key);
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    // 加密测试
    sm4.encrypt(test_plaintext, ciphertext);
    std::cout << "明文: ";
    printHex(test_plaintext, 16);
    std::cout << "密文: ";
    printHex(ciphertext, 16);
    
    bool encrypt_ok = memcmp(ciphertext, expected_ciphertext, 16) == 0;
    std::cout << "加密测试: " << (encrypt_ok ? "通过" : "失败") << std::endl;
    
    // 解密测试
    sm4.decrypt(ciphertext, decrypted);
    std::cout << "解密: ";
    printHex(decrypted, 16);
    
    bool decrypt_ok = memcmp(decrypted, test_plaintext, 16) == 0;
    std::cout << "解密测试: " << (decrypt_ok ? "通过" : "失败") << std::endl;
    
    return encrypt_ok && decrypt_ok;
}

#ifdef __x86_64__
bool testAESNISM4() {
    std::cout << "\n=== 测试AESNI优化SM4实现 ===" << std::endl;
    
    SM4::AESNI sm4;
    if (!sm4.isSupported()) {
        std::cout << "AESNI不支持，跳过测试" << std::endl;
        return true;
    }
    
    sm4.setKey(test_key);
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    // 加密测试
    sm4.encrypt(test_plaintext, ciphertext);
    std::cout << "明文: ";
    printHex(test_plaintext, 16);
    std::cout << "密文: ";
    printHex(ciphertext, 16);
    
    bool encrypt_ok = memcmp(ciphertext, expected_ciphertext, 16) == 0;
    std::cout << "加密测试: " << (encrypt_ok ? "通过" : "失败") << std::endl;
    
    // 解密测试
    sm4.decrypt(ciphertext, decrypted);
    std::cout << "解密: ";
    printHex(decrypted, 16);
    
    bool decrypt_ok = memcmp(decrypted, test_plaintext, 16) == 0;
    std::cout << "解密测试: " << (decrypt_ok ? "通过" : "失败") << std::endl;
    
    return encrypt_ok && decrypt_ok;
}

bool testModernISASM4() {
    std::cout << "\n=== 测试AVX/AVX2指令集优化SM4实现 ===" << std::endl;
    
    SM4::ModernISA sm4;
    if (!sm4.isSupported()) {
        std::cout << "AVX指令集不支持，跳过测试" << std::endl;
        return true;
    }
    
    sm4.setKey(test_key);
    
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    // 加密测试
    sm4.encrypt(test_plaintext, ciphertext);
    std::cout << "明文: ";
    printHex(test_plaintext, 16);
    std::cout << "密文: ";
    printHex(ciphertext, 16);
    
    bool encrypt_ok = memcmp(ciphertext, expected_ciphertext, 16) == 0;
    std::cout << "加密测试: " << (encrypt_ok ? "通过" : "失败") << std::endl;
    
    // 解密测试
    sm4.decrypt(ciphertext, decrypted);
    std::cout << "解密: ";
    printHex(decrypted, 16);
    
    bool decrypt_ok = memcmp(decrypted, test_plaintext, 16) == 0;
    std::cout << "解密测试: " << (decrypt_ok ? "通过" : "失败") << std::endl;
    
    return encrypt_ok && decrypt_ok;
}
#endif

bool testSM4GCM() {
    std::cout << "\n=== 测试SM4-GCM工作模式 ===" << std::endl;
    
    SM4_GCM gcm;
    
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };
    
    const char* plaintext_str = "Hello, SM4-GCM!";
    size_t pt_len = strlen(plaintext_str);
    
    uint8_t ciphertext[32];
    uint8_t tag[16];
    uint8_t decrypted[32];
    
    gcm.setKey(key);
    gcm.setIV(iv, 12);
    
    // 加密
    bool encrypt_ok = gcm.encrypt(reinterpret_cast<const uint8_t*>(plaintext_str), pt_len, 
                                 ciphertext, tag, 16);
    
    std::cout << "明文: " << plaintext_str << std::endl;
    std::cout << "密文: ";
    printHex(ciphertext, pt_len);
    std::cout << "标签: ";
    printHex(tag, 16);
    std::cout << "加密: " << (encrypt_ok ? "成功" : "失败") << std::endl;
    
    // 解密
    bool decrypt_ok = gcm.decrypt(ciphertext, pt_len, tag, 16, decrypted);
    
    if (decrypt_ok) {
        decrypted[pt_len] = '\0';
        std::cout << "解密: " << reinterpret_cast<char*>(decrypted) << std::endl;
    }
    std::cout << "解密: " << (decrypt_ok ? "成功" : "失败") << std::endl;
    
    return encrypt_ok && decrypt_ok;
}

void benchmarkImplementation(const std::string& name, std::function<void()> encrypt_func) {
    const int iterations = 100000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        encrypt_func();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = static_cast<double>(duration.count()) / iterations;
    double throughput = (16.0 * 1000000.0) / (avg_time * 1024 * 1024); // MB/s
    
    std::cout << name << ":" << std::endl;
    std::cout << "  平均时间: " << std::fixed << std::setprecision(2) << avg_time << " μs/block" << std::endl;
    std::cout << "  吞吐量: " << std::fixed << std::setprecision(2) << throughput << " MB/s" << std::endl;
}

void benchmarkBatchImplementation(const std::string& name, std::function<void()> encrypt_func, size_t block_count) {
    const int iterations = 10000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        encrypt_func();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_time = static_cast<double>(duration.count()) / (iterations * block_count);
    double throughput = (16.0 * 1000000.0) / (avg_time * 1024 * 1024); // MB/s
    
    std::cout << name << " (批量" << block_count << "块):" << std::endl;
    std::cout << "  平均时间: " << std::fixed << std::setprecision(2) << avg_time << " μs/block" << std::endl;
    std::cout << "  吞吐量: " << std::fixed << std::setprecision(2) << throughput << " MB/s" << std::endl;
}

void runPerformanceTests() {
    std::cout << "\n=== 性能测试 ===" << std::endl;
    
    // 准备测试数据
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    std::fill(plaintext, plaintext + 16, 0x55);
    
    // 基本实现
    SM4::Basic basic_sm4;
    basic_sm4.setKey(test_key);
    benchmarkImplementation("基本实现", [&]() {
        basic_sm4.encrypt(plaintext, ciphertext);
    });
    
    // T-table实现
    SM4::TTable ttable_sm4;
    ttable_sm4.setKey(test_key);
    benchmarkImplementation("T-table优化", [&]() {
        ttable_sm4.encrypt(plaintext, ciphertext);
    });
    
#ifdef __x86_64__
    // AESNI实现
    SM4::AESNI aesni_sm4;
    if (aesni_sm4.isSupported()) {
        aesni_sm4.setKey(test_key);
        benchmarkImplementation("AESNI优化", [&]() {
            aesni_sm4.encrypt(plaintext, ciphertext);
        });
    }
    
    // AVX/AVX2优化实现
    SM4::ModernISA modern_sm4;
    if (modern_sm4.isSupported()) {
        modern_sm4.setKey(test_key);
        benchmarkImplementation("AVX/AVX2优化", [&]() {
            modern_sm4.encrypt(plaintext, ciphertext);
        });
        
        // 批量处理性能测试 - SIMD的真正优势
        const size_t batch_size = 8;
        uint8_t batch_plaintext[16 * batch_size];
        uint8_t batch_ciphertext[16 * batch_size];
        
        // 初始化批量数据
        for (size_t i = 0; i < batch_size; i++) {
            std::memcpy(batch_plaintext + i * 16, plaintext, 16);
        }
        
        benchmarkBatchImplementation("AVX/AVX2批量优化", [&]() {
            modern_sm4.encryptBlocks(batch_plaintext, batch_ciphertext, batch_size);
        }, batch_size);
    }
#endif
}

int main() {
    std::cout << "SM4密码算法测试程序" << std::endl;
    std::cout << "===================" << std::endl;
    
    bool all_tests_passed = true;
    
    // 功能测试
    all_tests_passed &= testBasicSM4();
    all_tests_passed &= testTTableSM4();
    
#ifdef __x86_64__
    all_tests_passed &= testAESNISM4();
    all_tests_passed &= testModernISASM4();
#endif
    
    all_tests_passed &= testSM4GCM();
    
    // 性能测试
    runPerformanceTests();
    
    std::cout << "\n=== 测试总结 ===" << std::endl;
    std::cout << "所有测试: " << (all_tests_passed ? "通过" : "失败") << std::endl;
    
    return all_tests_passed ? 0 : 1;
}

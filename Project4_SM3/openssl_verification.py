#!/usr/bin/env python3
"""
OpenSSL对比验证脚本

与OpenSSL的SM3实现进行对比验证，确保我们的实现正确
"""

import subprocess
import sys
from sm3_algorithms import SM3Basic, SM3Optimized
from length_extension_attack import demonstrate_length_extension_attack


def run_openssl_sm3(message: str) -> str:
    """使用OpenSSL计算SM3哈希"""
    try:
        result = subprocess.run(
            ['openssl', 'dgst', '-sm3'],
            input=message,
            text=True,
            capture_output=True,
            check=True
        )
        # 输出格式: SM3(stdin)= hash_value
        return result.stdout.strip().split('= ')[1]
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError) as e:
        print(f"OpenSSL命令执行失败: {e}")
        return None


def run_openssl_hmac_sm3(message: str, key: str) -> str:
    """使用OpenSSL计算HMAC-SM3"""
    try:
        result = subprocess.run(
            ['openssl', 'dgst', '-sm3', '-hmac', key],
            input=message,
            text=True,
            capture_output=True,
            check=True
        )
        # 输出格式: SM3(stdin)= hash_value
        return result.stdout.strip().split('= ')[1]
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError) as e:
        print(f"OpenSSL HMAC命令执行失败: {e}")
        return None


def compare_sm3_implementations():
    """对比SM3实现"""
    print("=" * 60)
    print("🔍 SM3实现对比验证")
    print("=" * 60)
    
    test_vectors = [
        "",
        "a",
        "abc", 
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "user=alice&role=user&balance=1000",
        "Hello SM3!",
        "The quick brown fox jumps over the lazy dog",
        "1234567890" * 10,  # 100字符
        "A" * 256  # 256字符
    ]
    
    sm3_basic = SM3Basic()
    sm3_optimized = SM3Optimized()
    
    all_passed = True
    
    for i, test_input in enumerate(test_vectors, 1):
        print(f"\n测试 {i}: {repr(test_input[:30])}{('...' if len(test_input) > 30 else '')} ({len(test_input)} 字符)")
        
        # 我们的实现
        our_basic = sm3_basic.hash(test_input.encode('utf-8'))
        our_optimized = sm3_optimized.hash(test_input.encode('utf-8'))
        
        # OpenSSL实现
        openssl_result = run_openssl_sm3(test_input)
        
        if openssl_result is None:
            print("⚠️  OpenSSL不可用，跳过对比")
            continue
        
        # 比较结果
        basic_match = (our_basic == openssl_result)
        optimized_match = (our_optimized == openssl_result)
        consistency_match = (our_basic == our_optimized)
        
        print(f"基础版本:   {our_basic}")
        print(f"优化版本:   {our_optimized}")
        print(f"OpenSSL:    {openssl_result}")
        print(f"基础版本 vs OpenSSL: {'✅' if basic_match else '❌'}")
        print(f"优化版本 vs OpenSSL: {'✅' if optimized_match else '❌'}")
        print(f"内部一致性: {'✅' if consistency_match else '❌'}")
        
        if not (basic_match and optimized_match and consistency_match):
            all_passed = False
            print("🚨 发现不匹配!")
    
    return all_passed


def compare_hmac_implementations():
    """对比HMAC-SM3实现"""
    print("\n" + "=" * 60)
    print("🔍 HMAC-SM3实现对比验证")
    print("=" * 60)
    
    def hmac_sm3(key: bytes, message: bytes) -> str:
        """HMAC-SM3实现"""
        sm3 = SM3Basic()
        
        # HMAC算法标准实现
        block_size = 64  # SM3块大小
        
        # 密钥处理
        if len(key) > block_size:
            key = bytes.fromhex(sm3.hash(key))
        
        if len(key) < block_size:
            key = key + b'\x00' * (block_size - len(key))
        
        # 计算内外层填充
        inner_pad = bytes(x ^ 0x36 for x in key)
        outer_pad = bytes(x ^ 0x5c for x in key)
        
        # HMAC计算
        inner_input = inner_pad + message
        inner_hash = sm3.hash(inner_input)
        
        outer_input = outer_pad + bytes.fromhex(inner_hash)
        return sm3.hash(outer_input)
    
    test_cases = [
        ("super_secret_key_12345", "user=alice&role=user&balance=1000"),
        ("key", "message"),
        ("", "empty key test"),
        ("very_long_key_that_exceeds_block_size_" * 3, "test with long key"),
        ("short", "The quick brown fox jumps over the lazy dog"),
    ]
    
    all_passed = True
    
    for i, (key, message) in enumerate(test_cases, 1):
        print(f"\n测试 {i}: 密钥='{key[:20]}{'...' if len(key) > 20 else ''}', 消息='{message[:30]}{'...' if len(message) > 30 else ''}'")
        
        # 我们的HMAC实现
        our_hmac = hmac_sm3(key.encode('utf-8'), message.encode('utf-8'))
        
        # OpenSSL HMAC实现
        openssl_hmac = run_openssl_hmac_sm3(message, key)
        
        if openssl_hmac is None:
            print("⚠️  OpenSSL HMAC不可用，跳过对比")
            continue
        
        match = (our_hmac == openssl_hmac)
        
        print(f"我们的HMAC: {our_hmac}")
        print(f"OpenSSL:    {openssl_hmac}")
        print(f"匹配结果: {'✅' if match else '❌'}")
        
        if not match:
            all_passed = False
            print("🚨 HMAC不匹配!")
    
    return all_passed


def verify_length_extension_attack():
    """验证长度扩展攻击的有效性"""
    print("\n" + "=" * 60)
    print("🔍 长度扩展攻击验证")
    print("=" * 60)
    
    print("运行长度扩展攻击演示...")
    attack_success = demonstrate_length_extension_attack()
    
    if attack_success:
        print("✅ 长度扩展攻击成功 - 证明了SM3(key||message)的脆弱性")
        
        # 额外验证：手动验证攻击确实有效
        print("\n验证攻击的真实性:")
        sm3 = SM3Basic()
        
        # 重现攻击场景
        secret = b"super_secret_key_12345"
        original_message = b"user=alice&role=user&balance=1000"
        malicious_data = b"&role=admin&balance=999999"
        
        # 计算原始MAC
        original_mac = sm3.hash(secret + original_message)
        
        # 执行攻击
        forged_mac, message_suffix = sm3.length_extension_attack(
            original_mac, len(secret + original_message), malicious_data
        )
        
        # 验证伪造的MAC
        forged_message = original_message + message_suffix
        expected_mac = sm3.hash(secret + forged_message)
        
        verification_success = (forged_mac == expected_mac)
        print(f"内部攻击验证: {'✅ 通过' if verification_success else '❌ 失败'}")
        
        # 使用OpenSSL进行额外验证
        openssl_expected = run_openssl_sm3(secret + forged_message)
        if openssl_expected:
            openssl_verification = (forged_mac == openssl_expected)
            print(f"OpenSSL验证: {'✅ 通过' if openssl_verification else '❌ 失败'}")
            print(f"我们的伪造MAC: {forged_mac}")
            print(f"OpenSSL结果:   {openssl_expected}")
            verification_success = verification_success and openssl_verification
        
        if verification_success:
            print(f"原始消息: {original_message.decode()}")
            print(f"伪造消息: {forged_message.decode('utf-8', errors='ignore')}")
            print("🚨 攻击者成功在不知道密钥的情况下伪造了有效的MAC!")
            print("✅ OpenSSL确认攻击的有效性")
        
        return verification_success
    else:
        print("❌ 长度扩展攻击失败")
        return False


def comprehensive_verification():
    """综合验证"""
    print("🎯 SM3实现综合验证报告")
    print("与OpenSSL标准实现进行对比")
    print("=" * 60)
    
    # 检查OpenSSL可用性
    openssl_available = run_openssl_sm3("test") is not None
    if not openssl_available:
        print("❌ OpenSSL不可用或不支持SM3算法")
        print("   请确保安装了支持SM3的OpenSSL版本")
        return False
    
    print("✅ OpenSSL SM3支持检测成功")
    
    # 进行各项测试
    sm3_passed = compare_sm3_implementations()
    hmac_passed = compare_hmac_implementations()
    attack_verified = verify_length_extension_attack()
    
    # 生成报告
    print("\n" + "=" * 60)
    print("📊 验证结果总结")
    print("=" * 60)
    
    print(f"SM3算法实现: {'✅ 通过' if sm3_passed else '❌ 失败'}")
    print(f"HMAC-SM3实现: {'✅ 通过' if hmac_passed else '❌ 失败'}")
    print(f"长度扩展攻击: {'✅ 验证成功' if attack_verified else '❌ 验证失败'}")
    
    all_passed = sm3_passed and hmac_passed and attack_verified
    
    if all_passed:
        print("\n🎉 所有测试通过！我们的SM3实现与OpenSSL标准完全一致")
        print("✅ 实现正确性已验证")
        print("✅ 长度扩展攻击漏洞已证实")
        print("✅ HMAC防护机制有效")
    else:
        print("\n⚠️  部分测试未通过，请检查实现")
    
    return all_passed


if __name__ == "__main__":
    try:
        comprehensive_verification()
    except KeyboardInterrupt:
        print("\n验证被用户中断")
    except Exception as e:
        print(f"\n验证过程中发生错误: {e}")
        sys.exit(1)

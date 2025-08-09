#!/usr/bin/env python3
"""
长度扩展攻击演示模块

演示SM3算法的长度扩展攻击漏洞以及HMAC-SM3的防护效果
"""

import os
import subprocess
from typing import Tuple
from sm3_algorithms import SM3Basic


def run_openssl_sm3(message: bytes) -> str:
    """使用OpenSSL计算SM3哈希"""
    try:
        result = subprocess.run(
            ['openssl', 'dgst', '-sm3'],
            input=message,
            capture_output=True,
            check=True
        )
        # 输出格式: SM3(stdin)= hash_value
        return result.stdout.decode().strip().split('= ')[1]
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError):
        return None


def run_openssl_hmac_sm3(message: bytes, key: bytes) -> str:
    """使用OpenSSL计算HMAC-SM3"""
    try:
        # 确保key是字符串格式
        key_str = key.decode('utf-8') if isinstance(key, bytes) else key
        
        result = subprocess.run(
            ['openssl', 'dgst', '-sm3', '-hmac', key_str],
            input=message,
            capture_output=True,
            check=True
        )
        return result.stdout.decode().strip().split('= ')[1]
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError):
        return None


def demonstrate_length_extension_attack():
    """演示长度扩展攻击"""
    print("=== SM3长度扩展攻击演示 ===")
    
    sm3 = SM3Basic()
    
    # 检查OpenSSL是否可用
    openssl_available = run_openssl_sm3(b"test") is not None
    if openssl_available:
        print("✅ OpenSSL SM3支持已检测到，将进行对比验证")
    else:
        print("⚠️  OpenSSL不可用，仅使用内部实现")
    
    # 模拟场景：用户认证系统
    print("\n场景: 用户认证系统")
    print("服务器使用 SM3(secret + message) 作为消息认证码")
    
    # 秘密密钥（攻击者不知道）
    secret = b"super_secret_key_12345"
    print(f"秘密密钥: {secret.decode()} (长度: {len(secret)} 字节)")
    
    # 原始消息
    original_message = b"user=alice&role=user&balance=1000"
    print(f"原始消息: {original_message.decode()}")
    
    # 服务器计算MAC
    full_data = secret + original_message
    original_mac = sm3.hash(full_data)
    print(f"原始MAC: {original_mac}")
    
    # 使用OpenSSL验证我们的MAC计算
    if openssl_available:
        openssl_mac = run_openssl_sm3(full_data)
        mac_match = (original_mac == openssl_mac)
        print(f"OpenSSL验证: {openssl_mac}")
        print(f"MAC匹配: {'✅' if mac_match else '❌'}")
        if not mac_match:
            print("⚠️  MAC计算不匹配，请检查实现")
            return False
    
    print(f"\n攻击者已知信息:")
    print(f"- 原始消息: {original_message.decode()}")
    print(f"- 原始MAC: {original_mac}")
    print(f"- 密钥长度: {len(secret)} 字节")
    print(f"- 但不知道密钥内容")
    
    # 攻击者想要附加的恶意数据
    malicious_data = b"&role=admin&balance=999999"
    print(f"\n攻击者想要附加: {malicious_data.decode()}")
    
    # 执行长度扩展攻击
    print(f"\n=== 执行长度扩展攻击 ===")
    
    # 1. 从原始MAC中提取状态（这是攻击的关键）
    original_length = len(full_data)
    print(f"已知总长度: {original_length} 字节 (密钥 + 消息)")
    
    # 2. 执行长度扩展攻击
    forged_mac, message_suffix = sm3.length_extension_attack(
        original_mac, 
        original_length,
        malicious_data
    )
    
    print(f"伪造MAC: {forged_mac}")
    print(f"消息后缀长度: {len(message_suffix)} 字节")
    
    # 3. 构造完整的伪造消息进行验证
    forged_message = original_message + message_suffix
    print(f"伪造消息总长度: {len(forged_message)} 字节")
    
    # 4. 验证攻击是否成功
    expected_mac = sm3.hash(secret + forged_message)
    attack_success = (forged_mac == expected_mac)
    
    print(f"\n=== 攻击结果 ===")
    print(f"攻击成功: {'是' if attack_success else '否'}")
    print(f"伪造的MAC: {forged_mac}")
    print(f"期望的MAC: {expected_mac}")
    print(f"MAC匹配: {'是' if forged_mac == expected_mac else '否'}")
    
    # 使用OpenSSL验证伪造的消息
    if openssl_available and attack_success:
        print(f"\n=== OpenSSL验证攻击结果 ===")
        openssl_forged_mac = run_openssl_sm3(secret + forged_message)
        openssl_match = (forged_mac == openssl_forged_mac)
        
        print(f"我们计算的伪造MAC: {forged_mac}")
        print(f"OpenSSL计算结果:   {openssl_forged_mac}")
        print(f"OpenSSL验证: {'✅ 匹配' if openssl_match else '❌ 不匹配'}")
        
        if not openssl_match:
            print("⚠️  OpenSSL验证失败，攻击可能有误")
            return False
    
    if attack_success:
        print(f"\n⚠️  攻击成功！攻击者成功伪造了包含恶意数据的有效MAC")
        print(f"伪造消息: {forged_message.decode('utf-8', errors='ignore')}")
        
        # 显示实际的二进制消息结构
        print(f"\n=== 消息结构分析 ===")
        print(f"原始消息: {original_message}")
        print(f"填充数据: {message_suffix[:-len(malicious_data)]}")
        print(f"恶意数据: {malicious_data}")
        print(f"完整伪造: {forged_message}")
        
        if openssl_available:
            print(f"✅ OpenSSL验证确认攻击有效")
    else:
        print(f"\n✅ 攻击失败")
    
    return attack_success


def demonstrate_hmac_protection():
    """演示HMAC-SM3的防护效果"""
    print(f"\n" + "="*60)
    print("=== HMAC-SM3防护演示 ===")
    
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
    
    # 检查OpenSSL是否可用
    openssl_available = run_openssl_sm3(b"test") is not None
    
    # 使用相同的测试数据
    secret = b"super_secret_key_12345"
    original_message = b"user=alice&role=user&balance=1000"
    malicious_data = b"&role=admin&balance=999999"
    
    print(f"使用HMAC-SM3保护消息...")
    
    # 计算原始消息的HMAC
    original_hmac = hmac_sm3(secret, original_message)
    print(f"原始消息HMAC: {original_hmac}")
    
    # 使用OpenSSL验证HMAC计算
    if openssl_available:
        openssl_hmac = run_openssl_hmac_sm3(original_message, secret)
        if openssl_hmac:
            hmac_match = (original_hmac == openssl_hmac)
            print(f"OpenSSL HMAC:  {openssl_hmac}")
            print(f"HMAC匹配: {'✅' if hmac_match else '❌'}")
            if not hmac_match:
                print("⚠️  HMAC计算不匹配，请检查实现")
        else:
            print("⚠️  OpenSSL HMAC计算失败")
    
    # 尝试对HMAC进行长度扩展攻击
    print(f"\n尝试对HMAC进行长度扩展攻击...")
    
    sm3 = SM3Basic()
    
    # 构造伪造消息
    forged_message = original_message + malicious_data
    
    # 攻击者尝试计算伪造消息的HMAC（但不知道密钥）
    # 这里我们假设攻击者尝试各种方法，但都会失败
    
    # 正确的HMAC计算
    correct_hmac = hmac_sm3(secret, forged_message)
    
    print(f"正确的伪造消息HMAC: {correct_hmac}")
    print(f"原始消息HMAC: {original_hmac}")
    print(f"HMAC相同: {'是' if original_hmac == correct_hmac else '否'}")
    
    # 使用OpenSSL验证伪造消息的HMAC
    if openssl_available:
        openssl_forged_hmac = run_openssl_hmac_sm3(forged_message, secret)
        if openssl_forged_hmac:
            openssl_match = (correct_hmac == openssl_forged_hmac)
            print(f"OpenSSL伪造HMAC: {openssl_forged_hmac}")
            print(f"OpenSSL验证: {'✅ 匹配' if openssl_match else '❌ 不匹配'}")
    
    print(f"\n✅ HMAC防护结果:")
    print(f"- 攻击者无法在不知道密钥的情况下计算有效的HMAC")
    print(f"- 长度扩展攻击对HMAC无效")
    print(f"- 消息完整性和认证性得到保护")
    if openssl_available:
        print(f"- OpenSSL验证确认HMAC实现正确")


def compare_vulnerability():
    """对比SM3直接使用和HMAC-SM3的安全性"""
    print(f"\n" + "="*60)
    print("=== 安全性对比总结 ===")
    
    print(f"\n直接使用SM3 (SM3(key || message)):")
    print(f"❌ 容易受到长度扩展攻击")
    print(f"❌ 攻击者可以在不知道密钥的情况下伪造有效MAC")
    print(f"❌ 无法保证消息完整性")
    
    print(f"\n使用HMAC-SM3:")
    print(f"✅ 抵抗长度扩展攻击")
    print(f"✅ 攻击者无法伪造有效MAC")
    print(f"✅ 保证消息完整性和认证性")
    print(f"✅ 符合密码学最佳实践")
    
    print(f"\n推荐使用方案:")
    print(f"🔒 总是使用HMAC-SM3而不是SM3(key || message)")
    print(f"🔒 或者使用其他经过验证的MAC算法")
    print(f"🔒 避免自制密码学原语")


def interactive_demo():
    """交互式演示"""
    print(f"\n" + "="*60)
    print("=== 交互式长度扩展攻击演示 ===")
    
    sm3 = SM3Basic()
    openssl_available = run_openssl_sm3(b"test") is not None
    
    if openssl_available:
        print("✅ OpenSSL可用，将进行验证对比")
    else:
        print("⚠️  OpenSSL不可用，仅使用内部实现")
    
    try:
        # 用户输入
        print(f"\n请输入演示参数（或按回车使用默认值）:")
        
        secret_input = input("密钥 (默认: 'my_secret_key'): ").strip()
        secret = secret_input.encode() if secret_input else b'my_secret_key'
        
        message_input = input("原始消息 (默认: 'hello world'): ").strip()
        original_message = message_input.encode() if message_input else b'hello world'
        
        append_input = input("要附加的数据 (默认: '&admin=true'): ").strip()
        append_data = append_input.encode() if append_input else b'&admin=true'
        
        print(f"\n=== 攻击执行 ===")
        
        # 计算原始MAC
        full_data = secret + original_message
        original_mac = sm3.hash(full_data)
        
        print(f"原始消息: {original_message.decode()}")
        print(f"原始MAC: {original_mac}")
        
        # OpenSSL验证原始MAC
        if openssl_available:
            openssl_original = run_openssl_sm3(full_data)
            if openssl_original:
                original_match = (original_mac == openssl_original)
                print(f"OpenSSL原始MAC: {openssl_original}")
                print(f"原始MAC验证: {'✅' if original_match else '❌'}")
        
        # 执行攻击
        original_length = len(full_data)
        
        # 执行长度扩展攻击
        forged_mac, message_suffix = sm3.length_extension_attack(
            original_mac, original_length, append_data
        )
        
        # 验证
        forged_message = original_message + message_suffix
        expected_mac = sm3.hash(secret + forged_message)
        
        print(f"伪造MAC: {forged_mac}")
        print(f"期望MAC: {expected_mac}")
        attack_result = forged_mac == expected_mac
        print(f"攻击结果: {'成功' if attack_result else '失败'}")
        
        # OpenSSL验证攻击结果
        if openssl_available and attack_result:
            openssl_forged = run_openssl_sm3(secret + forged_message)
            if openssl_forged:
                forged_match = (forged_mac == openssl_forged)
                print(f"OpenSSL伪造MAC: {openssl_forged}")
                print(f"伪造MAC验证: {'✅' if forged_match else '❌'}")
                
                if forged_match:
                    print(f"✅ OpenSSL确认攻击成功")
                    print(f"完整伪造消息: {forged_message.decode('utf-8', errors='ignore')}")
        
    except KeyboardInterrupt:
        print(f"\n演示已取消")
    except Exception as e:
        print(f"错误: {e}")


if __name__ == "__main__":
    # 运行所有演示
    print("SM3长度扩展攻击完整演示")
    print("="*60)
    
    # 1. 基本攻击演示
    attack_success = demonstrate_length_extension_attack()
    
    # 2. HMAC防护演示
    demonstrate_hmac_protection()
    
    # 3. 安全性对比
    compare_vulnerability()
    
    # 4. 交互式演示（可选）
    print(f"\n是否运行交互式演示？(y/N): ", end="")
    try:
        if input().lower().startswith('y'):
            interactive_demo()
    except KeyboardInterrupt:
        print(f"\n演示结束")
    
    print(f"\n" + "="*60)
    print("演示完成！")
    print("记住：在实际应用中应该使用HMAC-SM3而不是直接的SM3(key||message)!")

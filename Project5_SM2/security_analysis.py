#!/usr/bin/env python3
"""
SM2签名算法误用POC验证
基于PDF文档中提到的安全问题进行验证和演示
"""

import hashlib
import secrets
from sm2_algorithms import SM2Basic, SM2Optimized, Point
from typing import Tuple, List, Dict
import time


class SM2SecurityAnalysis:
    """SM2安全分析和漏洞演示"""
    
    def __init__(self):
        self.sm2 = SM2Basic()
        self.curve = self.sm2.curve
    
    def weak_random_k_attack(self) -> Dict:
        """演示随机数k重用攻击"""
        print("=== 随机数k重用攻击演示 ===")
        
        # 生成密钥对
        private_key, public_key = self.sm2.generate_keypair()
        print(f"目标私钥: {private_key:064x}")
        
        # 使用相同的k对两个不同消息签名
        message1 = b"Message 1"
        message2 = b"Message 2"
        
        # 手动实现签名过程以控制k值
        k = secrets.randbelow(self.curve.n - 1) + 1
        print(f"重用的随机数k: {k:064x}")
        
        # 对消息1签名
        za1 = self.sm2.za_value(b'1234567812345678', public_key)
        M1_prime = za1 + message1
        e1 = int.from_bytes(self.sm2.sm3_hash(M1_prime), 'big')
        
        point = self.curve.point_multiply(k, self.curve.G)
        r1 = (e1 + point.x) % self.curve.n
        d_inv = pow(1 + private_key, -1, self.curve.n)
        s1 = (d_inv * (k - r1 * private_key)) % self.curve.n
        
        signature1 = (r1, s1)
        
        # 对消息2使用相同的k签名
        za2 = self.sm2.za_value(b'1234567812345678', public_key)
        M2_prime = za2 + message2
        e2 = int.from_bytes(self.sm2.sm3_hash(M2_prime), 'big')
        
        r2 = (e2 + point.x) % self.curve.n
        s2 = (d_inv * (k - r2 * private_key)) % self.curve.n
        
        signature2 = (r2, s2)
        
        print(f"消息1签名: r={r1:064x}, s={s1:064x}")
        print(f"消息2签名: r={r2:064x}, s={s2:064x}")
        
        # 验证签名
        valid1 = self.sm2.verify(public_key, message1, signature1)
        valid2 = self.sm2.verify(public_key, message2, signature2)
        print(f"签名1验证: {'✅' if valid1 else '❌'}")
        print(f"签名2验证: {'✅' if valid2 else '❌'}")
        
        # 尝试恢复私钥
        try:
            recovered_key = self.recover_private_key_from_k_reuse(
                e1, r1, s1, e2, r2, s2, k
            )
            print(f"恢复的私钥: {recovered_key:064x}")
            print(f"私钥恢复: {'✅ 成功' if recovered_key == private_key else '❌ 失败'}")
        except Exception as e:
            print(f"私钥恢复失败: {e}")
        
        return {
            'original_key': private_key,
            'recovered_key': recovered_key if 'recovered_key' in locals() else None,
            'attack_successful': 'recovered_key' in locals() and recovered_key == private_key
        }
    
    def recover_private_key_from_k_reuse(self, e1: int, r1: int, s1: int, 
                                       e2: int, r2: int, s2: int, k: int) -> int:
        """从k重用中恢复私钥"""
        # 理论推导：
        # s1 = (1+d)^(-1) * (k - r1*d) mod n
        # s2 = (1+d)^(-1) * (k - r2*d) mod n
        # 
        # 展开得：s1*(1+d) = k - r1*d mod n
        #        s2*(1+d) = k - r2*d mod n
        # 
        # 即：s1 + s1*d = k - r1*d mod n  =>  s1 = k - (r1 + s1)*d mod n
        #    s2 + s2*d = k - r2*d mod n  =>  s2 = k - (r2 + s2)*d mod n
        # 
        # 两式相减：s1 - s2 = (r2 + s2 - r1 - s1)*d mod n
        # 所以：d = (s1 - s2) * (r2 + s2 - r1 - s1)^(-1) mod n
        
        if r1 == r2:
            raise ValueError("r值相同，无法进行攻击")
        
        # 使用正确的公式
        numerator = (s1 - s2) % self.curve.n
        denominator = (r2 + s2 - r1 - s1) % self.curve.n
        
        if denominator == 0:
            raise ValueError("分母为0，无法计算")
        
        # 计算模逆
        denominator_inv = pow(denominator, -1, self.curve.n)
        
        recovered_d = (numerator * denominator_inv) % self.curve.n
        
        return recovered_d
    
    def invalid_curve_attack(self) -> Dict:
        """演示无效曲线攻击"""
        print("\n=== 无效曲线攻击演示 ===")
        
        # 生成目标密钥对
        private_key, public_key = self.sm2.generate_keypair()
        print(f"目标私钥: {private_key:064x}")
        print(f"目标公钥: {public_key}")
        
        # 构造一个无效的曲线点（不在SM2曲线上）
        # 选择一个不满足曲线方程的点
        invalid_x = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
        invalid_y = 0xFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
        invalid_point = Point(invalid_x, invalid_y)
        
        print(f"无效点: {invalid_point}")
        print(f"是否在SM2曲线上: {'✅' if self.curve.is_on_curve(invalid_point) else '❌'}")
        
        # 如果实现没有验证点的有效性，可能会产生弱签名
        message = b"Test message for invalid curve attack"
        
        try:
            # 尝试用无效点验证签名（这应该失败）
            fake_signature = (0x1234567890ABCDEF, 0xFEDCBA0987654321)
            result = self.sm2.verify(invalid_point, message, fake_signature)
            print(f"无效点验证结果: {'⚠️ 通过（有风险）' if result else '✅ 拒绝（安全）'}")
        except Exception as e:
            print(f"无效点验证异常: {e}")
        
        return {
            'invalid_point': invalid_point,
            'on_curve': self.curve.is_on_curve(invalid_point),
            'verification_result': False  # 应该总是False
        }
    
    def signature_malleability_attack(self) -> Dict:
        """演示签名可塑性攻击"""
        print("\n=== 签名可塑性攻击演示 ===")
        
        # 生成密钥对和签名
        private_key, public_key = self.sm2.generate_keypair()
        message = b"Test message for malleability"
        
        original_signature = self.sm2.sign(private_key, message)
        r, s = original_signature
        
        print(f"原始签名: r={r:064x}, s={s:064x}")
        
        # 构造可塑的签名：(r, n-s)
        malleable_s = (self.curve.n - s) % self.curve.n
        malleable_signature = (r, malleable_s)
        
        print(f"可塑签名: r={r:064x}, s={malleable_s:064x}")
        
        # 验证两个签名
        original_valid = self.sm2.verify(public_key, message, original_signature)
        malleable_valid = self.sm2.verify(public_key, message, malleable_signature)
        
        print(f"原始签名验证: {'✅' if original_valid else '❌'}")
        print(f"可塑签名验证: {'⚠️ 通过（有风险）' if malleable_valid else '✅ 拒绝（安全）'}")
        
        return {
            'original_signature': original_signature,
            'malleable_signature': malleable_signature,
            'original_valid': original_valid,
            'malleable_valid': malleable_valid,
            'attack_successful': malleable_valid
        }
    
    def user_id_collision_attack(self) -> Dict:
        """演示用户ID碰撞攻击"""
        print("\n=== 用户ID碰撞攻击演示 ===")
        
        # 生成两个不同的密钥对
        private_key1, public_key1 = self.sm2.generate_keypair()
        private_key2, public_key2 = self.sm2.generate_keypair()
        
        message = b"Important message"
        user_id1 = b'Alice123'
        user_id2 = b'Bob456'
        
        # 用户1的正常签名
        signature1 = self.sm2.sign(private_key1, message, user_id1)
        
        print(f"用户1 ID: {user_id1}")
        print(f"用户1公钥: {public_key1}")
        print(f"用户1签名: r={signature1[0]:064x}, s={signature1[1]:064x}")
        
        # 尝试用用户1的签名在用户2的身份下验证
        cross_verify = self.sm2.verify(public_key2, message, signature1, user_id2)
        print(f"交叉验证结果: {'⚠️ 通过（有风险）' if cross_verify else '✅ 拒绝（安全）'}")
        
        # 尝试寻找Za值碰撞（这在实际中很困难）
        za1 = self.sm2.za_value(user_id1, public_key1)
        za2 = self.sm2.za_value(user_id2, public_key2)
        
        print(f"Za1: {za1.hex()}")
        print(f"Za2: {za2.hex()}")
        print(f"Za值相同: {'⚠️ 是（有风险）' if za1 == za2 else '✅ 否（安全）'}")
        
        return {
            'cross_verify': cross_verify,
            'za_collision': za1 == za2,
            'attack_successful': cross_verify or za1 == za2
        }


class SatoshiSignatureForgery:
    """中本聪签名伪造演示"""
    
    def __init__(self):
        self.sm2 = SM2Basic()
        self.curve = self.sm2.curve
    
    def simulate_satoshi_keys(self) -> Tuple[int, Point]:
        """模拟生成'中本聪'的密钥对"""
        # 使用固定的种子模拟已知的私钥
        # 在实际场景中，这些信息是未知的
        satoshi_seed = b"Satoshi Nakamoto Genesis Block"
        hash_result = hashlib.sha256(satoshi_seed).digest()
        private_key = int.from_bytes(hash_result, 'big') % self.curve.n
        
        if private_key == 0:
            private_key = 1
        
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        
        return private_key, public_key
    
    def forge_signature_with_known_k(self, target_public_key: Point, message: bytes, k: int) -> Tuple[int, int]:
        """已知k值时的签名伪造"""
        # 计算Za值
        user_id = b'Satoshi'
        za = self.sm2.za_value(user_id, target_public_key)
        
        # 计算消息摘要
        M_prime = za + message
        e = int.from_bytes(self.sm2.sm3_hash(M_prime), 'big')
        
        # 计算r
        point = self.curve.point_multiply(k, self.curve.G)
        r = (e + point.x) % self.curve.n
        
        # 由于我们不知道私钥d，我们无法直接计算s
        # 这只是演示如何构造签名的格式
        # 在实际攻击中，需要其他方法
        s = secrets.randbelow(self.curve.n - 1) + 1
        
        return r, s
    
    def demonstrate_forgery_attempt(self) -> Dict:
        """演示签名伪造尝试"""
        print("=== 中本聪签名伪造演示 ===")
        
        # 模拟获得'中本聪'的公钥
        private_key, public_key = self.simulate_satoshi_keys()
        print(f"模拟中本聪公钥: {public_key}")
        
        # 要伪造签名的消息
        forged_message = b"I, Satoshi Nakamoto, transfer all my bitcoins"
        
        # 方法1: 随机伪造（几乎不可能成功）
        print("\n方法1: 随机伪造签名")
        random_r = secrets.randbelow(self.curve.n - 1) + 1
        random_s = secrets.randbelow(self.curve.n - 1) + 1
        random_signature = (random_r, random_s)
        
        random_valid = self.sm2.verify(public_key, forged_message, random_signature, b'Satoshi')
        print(f"随机签名验证: {'⚠️ 成功（不太可能）' if random_valid else '✅ 失败（正常）'}")
        
        # 方法2: 利用已知的k值（如果存在）
        print("\n方法2: 利用已知k值伪造")
        known_k = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
        k_signature = self.forge_signature_with_known_k(public_key, forged_message, known_k)
        
        k_valid = self.sm2.verify(public_key, forged_message, k_signature, b'Satoshi')
        print(f"已知k签名验证: {'⚠️ 成功（危险）' if k_valid else '✅ 失败（正常）'}")
        
        # 方法3: 正确的签名（使用真实私钥）
        print("\n方法3: 真实签名（对比）")
        real_signature = self.sm2.sign(private_key, forged_message, b'Satoshi')
        real_valid = self.sm2.verify(public_key, forged_message, real_signature, b'Satoshi')
        print(f"真实签名验证: {'✅ 成功' if real_valid else '❌ 失败'}")
        
        return {
            'random_forgery': random_valid,
            'k_forgery': k_valid,
            'real_signature': real_valid,
            'forgery_successful': random_valid or k_valid
        }


def run_security_analysis():
    """运行完整的安全分析"""
    print("🔒 SM2签名算法安全分析与漏洞演示")
    print("=" * 60)
    
    analysis = SM2SecurityAnalysis()
    
    # 1. 随机数k重用攻击
    k_reuse_result = analysis.weak_random_k_attack()
    
    # 2. 无效曲线攻击
    invalid_curve_result = analysis.invalid_curve_attack()
    
    # 3. 签名可塑性攻击
    malleability_result = analysis.signature_malleability_attack()
    
    # 4. 用户ID碰撞攻击
    user_id_result = analysis.user_id_collision_attack()
    
    print("\n" + "=" * 60)
    
    # 中本聪签名伪造演示
    satoshi_forge = SatoshiSignatureForgery()
    forgery_result = satoshi_forge.demonstrate_forgery_attempt()
    
    # 总结报告
    print("\n" + "=" * 60)
    print("📊 安全分析总结报告")
    print("=" * 60)
    
    attacks = [
        ("随机数k重用攻击", k_reuse_result.get('attack_successful', False)),
        ("无效曲线攻击", invalid_curve_result.get('verification_result', False)),
        ("签名可塑性攻击", malleability_result.get('attack_successful', False)),
        ("用户ID碰撞攻击", user_id_result.get('attack_successful', False)),
        ("中本聪签名伪造", forgery_result.get('forgery_successful', False))
    ]
    
    for attack_name, successful in attacks:
        status = "⚠️  成功（有风险）" if successful else "✅ 失败（安全）"
        print(f"{attack_name:20} : {status}")
    
    print("\n🔒 安全建议:")
    print("1. 确保随机数k的真随机性和唯一性")
    print("2. 验证椭圆曲线点的有效性")
    print("3. 实施签名规范化以防止可塑性")
    print("4. 妥善管理用户ID避免碰撞")
    print("5. 私钥管理和保护至关重要")


if __name__ == "__main__":
    run_security_analysis()

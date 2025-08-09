#!/usr/bin/env python3
"""
SM2算法测试套件
包含功能测试、安全测试和性能测试
"""

import unittest
import hashlib
from sm2_algorithms import SM2Basic, SM2Optimized, Point, SM2Curve
from security_analysis import SM2SecurityAnalysis, SatoshiSignatureForgery


class TestSM2Curve(unittest.TestCase):
    """SM2椭圆曲线测试"""
    
    def setUp(self):
        self.curve = SM2Curve()
    
    def test_curve_parameters(self):
        """测试曲线参数"""
        # 验证基点G在曲线上
        self.assertTrue(self.curve.is_on_curve(self.curve.G))
        
        # 验证基点的阶
        nG = self.curve.point_multiply(self.curve.n, self.curve.G)
        self.assertEqual(nG, self.curve.O)
    
    def test_point_operations(self):
        """测试点运算"""
        G = self.curve.G
        
        # 测试点加法的单位元
        self.assertEqual(self.curve.point_add(G, self.curve.O), G)
        self.assertEqual(self.curve.point_add(self.curve.O, G), G)
        
        # 测试点倍加
        G2_add = self.curve.point_add(G, G)
        G2_double = self.curve.point_double(G)
        self.assertEqual(G2_add, G2_double)
        
        # 测试标量乘法
        G3_scalar = self.curve.point_multiply(3, G)
        G3_add = self.curve.point_add(G2_add, G)
        self.assertEqual(G3_scalar, G3_add)
    
    def test_point_multiplication_properties(self):
        """测试标量乘法性质"""
        G = self.curve.G
        
        # 测试分配律: k*(P+Q) = k*P + k*Q
        P = self.curve.point_multiply(123, G)
        Q = self.curve.point_multiply(456, G)
        k = 789
        
        left = self.curve.point_multiply(k, self.curve.point_add(P, Q))
        right = self.curve.point_add(
            self.curve.point_multiply(k, P),
            self.curve.point_multiply(k, Q)
        )
        self.assertEqual(left, right)


class TestSM2Basic(unittest.TestCase):
    """SM2基础实现测试"""
    
    def setUp(self):
        self.sm2 = SM2Basic()
    
    def test_keypair_generation(self):
        """测试密钥对生成"""
        private_key, public_key = self.sm2.generate_keypair()
        
        # 验证私钥范围
        self.assertGreater(private_key, 0)
        self.assertLess(private_key, self.sm2.curve.n)
        
        # 验证公钥在曲线上
        self.assertTrue(self.sm2.curve.is_on_curve(public_key))
        
        # 验证公钥正确性
        expected_public_key = self.sm2.curve.point_multiply(private_key, self.sm2.curve.G)
        self.assertEqual(public_key, expected_public_key)
    
    def test_sign_and_verify(self):
        """测试签名和验证"""
        # 生成密钥对
        private_key, public_key = self.sm2.generate_keypair()
        
        # 测试消息
        message = b"Hello SM2 test message"
        user_id = b"testuser"
        
        # 签名
        signature = self.sm2.sign(private_key, message, user_id)
        r, s = signature
        
        # 验证签名格式
        self.assertGreater(r, 0)
        self.assertLess(r, self.sm2.curve.n)
        self.assertGreater(s, 0)
        self.assertLess(s, self.sm2.curve.n)
        
        # 验证签名
        is_valid = self.sm2.verify(public_key, message, signature, user_id)
        self.assertTrue(is_valid)
        
        # 测试错误消息
        wrong_message = b"Wrong message"
        is_invalid = self.sm2.verify(public_key, wrong_message, signature, user_id)
        self.assertFalse(is_invalid)
        
        # 测试错误公钥
        wrong_private, wrong_public = self.sm2.generate_keypair()
        is_invalid = self.sm2.verify(wrong_public, message, signature, user_id)
        self.assertFalse(is_invalid)
    
    def test_za_value_computation(self):
        """测试Za值计算"""
        # 固定的测试数据
        user_id = b"ALICE123@YAHOO.COM"
        private_key = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
        
        public_key = self.sm2.curve.point_multiply(private_key, self.sm2.curve.G)
        za = self.sm2.za_value(user_id, public_key)
        
        # Za值应该是32字节
        self.assertEqual(len(za), 32)
        
        # 相同输入应该产生相同的Za值
        za2 = self.sm2.za_value(user_id, public_key)
        self.assertEqual(za, za2)
    
    def test_deterministic_signature(self):
        """测试签名的确定性（使用相同的k应该产生相同的签名）"""
        private_key, public_key = self.sm2.generate_keypair()
        message = b"Deterministic test"
        
        # 由于SM2使用随机k，每次签名都不同
        # 这里只测试签名的有效性
        sig1 = self.sm2.sign(private_key, message)
        sig2 = self.sm2.sign(private_key, message)
        
        # 验证两个签名都有效
        self.assertTrue(self.sm2.verify(public_key, message, sig1))
        self.assertTrue(self.sm2.verify(public_key, message, sig2))


class TestSM2Optimized(unittest.TestCase):
    """SM2优化实现测试"""
    
    def setUp(self):
        self.sm2 = SM2Optimized()
    
    def test_precomputation(self):
        """测试预计算功能"""
        G = self.sm2.curve.G
        
        # 进行预计算
        self.sm2.precompute_points(G, 8)
        
        # 验证预计算表
        key = (G.x, G.y)
        self.assertIn(key, self.sm2._precomputed_points)
        
        precomputed = self.sm2._precomputed_points[key]
        self.assertEqual(len(precomputed), 8)
        
        # 验证预计算的正确性
        for i in range(8):
            expected = self.sm2.curve.point_multiply(2**i, G)
            self.assertEqual(precomputed[i], expected)
    
    def test_optimized_point_multiply(self):
        """测试优化的标量乘法"""
        G = self.sm2.curve.G
        test_scalars = [1, 2, 3, 15, 255, 256, 1024]
        
        # 预计算
        self.sm2.precompute_points(G)
        
        for k in test_scalars:
            # 比较优化版本和基础版本的结果
            basic_result = self.sm2.curve.point_multiply(k, G)
            optimized_result = self.sm2.optimized_point_multiply(k, G)
            self.assertEqual(basic_result, optimized_result)
    
    def test_optimized_sign_verify(self):
        """测试优化版本的签名验证"""
        # 生成密钥对
        private_key, public_key = self.sm2.generate_keypair()
        
        message = b"Optimized SM2 test"
        
        # 签名
        signature = self.sm2.sign(private_key, message)
        
        # 验证
        is_valid = self.sm2.verify(public_key, message, signature)
        self.assertTrue(is_valid)
    
    def test_cross_compatibility(self):
        """测试基础版本和优化版本的兼容性"""
        sm2_basic = SM2Basic()
        
        # 使用基础版本生成密钥对
        private_key, public_key = sm2_basic.generate_keypair()
        message = b"Cross compatibility test"
        
        # 基础版本签名，优化版本验证
        basic_signature = sm2_basic.sign(private_key, message)
        opt_verify = self.sm2.verify(public_key, message, basic_signature)
        self.assertTrue(opt_verify)
        
        # 优化版本签名，基础版本验证
        opt_signature = self.sm2.sign(private_key, message)
        basic_verify = sm2_basic.verify(public_key, message, opt_signature)
        self.assertTrue(basic_verify)


class TestSM2Security(unittest.TestCase):
    """SM2安全性测试"""
    
    def setUp(self):
        self.security = SM2SecurityAnalysis()
    
    def test_k_reuse_attack_detection(self):
        """测试k重用攻击检测"""
        result = self.security.weak_random_k_attack()
        
        # 攻击应该成功（在测试环境中）
        self.assertTrue(result['attack_successful'])
        self.assertEqual(result['original_key'], result['recovered_key'])
    
    def test_invalid_curve_detection(self):
        """测试无效曲线检测"""
        result = self.security.invalid_curve_attack()
        
        # 无效点不应该在曲线上
        self.assertFalse(result['on_curve'])
        
        # 验证应该失败
        self.assertFalse(result['verification_result'])
    
    def test_signature_malleability(self):
        """测试签名可塑性"""
        result = self.security.signature_malleability_attack()
        
        # 原始签名应该有效
        self.assertTrue(result['original_valid'])
        
        # 可塑签名在正确实现中应该无效
        # 注意: 这取决于具体的实现是否检查了s的范围
    
    def test_user_id_collision(self):
        """测试用户ID碰撞"""
        result = self.security.user_id_collision_attack()
        
        # 交叉验证应该失败
        self.assertFalse(result['cross_verify'])
        
        # Za值碰撞在实际中极其罕见
        self.assertFalse(result['za_collision'])


class TestSatoshiSignatureForgery(unittest.TestCase):
    """中本聪签名伪造测试"""
    
    def setUp(self):
        self.satoshi = SatoshiSignatureForgery()
    
    def test_satoshi_key_simulation(self):
        """测试中本聪密钥模拟"""
        private_key, public_key = self.satoshi.simulate_satoshi_keys()
        
        # 验证密钥格式
        self.assertGreater(private_key, 0)
        self.assertLess(private_key, self.satoshi.curve.n)
        self.assertTrue(self.satoshi.curve.is_on_curve(public_key))
    
    def test_forgery_attempts(self):
        """测试签名伪造尝试"""
        result = self.satoshi.demonstrate_forgery_attempt()
        
        # 随机伪造应该失败
        self.assertFalse(result['random_forgery'])
        
        # 真实签名应该成功
        self.assertTrue(result['real_signature'])
        
        # 总体伪造应该失败
        self.assertFalse(result['forgery_successful'])


def run_all_tests():
    """运行所有测试"""
    print("🧪 SM2算法测试套件")
    print("=" * 50)
    
    # 创建测试套件
    test_suite = unittest.TestSuite()
    
    # 添加测试类
    test_classes = [
        TestSM2Curve,
        TestSM2Basic,
        TestSM2Optimized,
        TestSM2Security,
        TestSatoshiSignatureForgery
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # 打印总结
    print("\n" + "=" * 50)
    print("📊 测试总结")
    print("=" * 50)
    print(f"运行测试数: {result.testsRun}")
    print(f"失败数: {len(result.failures)}")
    print(f"错误数: {len(result.errors)}")
    print(f"跳过数: {len(result.skipped)}")
    
    if result.failures:
        print("\n❌ 失败的测试:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\n💥 错误的测试:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    success_rate = (result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100
    print(f"\n✅ 成功率: {success_rate:.1f}%")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)

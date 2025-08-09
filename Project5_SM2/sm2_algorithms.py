#!/usr/bin/env python3
"""
SM2 椭圆曲线公钥密码算法实现
包含基础版本和优化版本
"""

import hashlib
import secrets
from typing import Tuple, Optional, Union
from dataclasses import dataclass
import struct


@dataclass
class Point:
    """椭圆曲线上的点"""
    x: int
    y: int
    
    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        return False
    
    def __str__(self):
        return f"({self.x:064x}, {self.y:064x})"


class SM2Curve:
    """SM2推荐椭圆曲线参数"""
    
    # SM2推荐曲线参数
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
    Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
    
    def __init__(self):
        self.G = Point(self.Gx, self.Gy)
        self.O = Point(0, 0)  # 无穷远点
    
    def is_on_curve(self, point: Point) -> bool:
        """检查点是否在曲线上"""
        if point == self.O:
            return True
        
        x, y = point.x, point.y
        return (y * y) % self.p == (x * x * x + self.a * x + self.b) % self.p
    
    def point_add(self, P: Point, Q: Point) -> Point:
        """椭圆曲线点加法"""
        if P == self.O:
            return Q
        if Q == self.O:
            return P
        
        if P.x == Q.x:
            if P.y == Q.y:
                # 点倍加
                return self.point_double(P)
            else:
                # P + (-P) = O
                return self.O
        
        # 一般情况的点加法
        dx = (Q.x - P.x) % self.p
        dy = (Q.y - P.y) % self.p
        s = (dy * pow(dx, -1, self.p)) % self.p
        
        x3 = (s * s - P.x - Q.x) % self.p
        y3 = (s * (P.x - x3) - P.y) % self.p
        
        return Point(x3, y3)
    
    def point_double(self, P: Point) -> Point:
        """椭圆曲线点倍加"""
        if P == self.O:
            return self.O
        
        # 计算切线斜率
        numerator = (3 * P.x * P.x + self.a) % self.p
        denominator = (2 * P.y) % self.p
        s = (numerator * pow(denominator, -1, self.p)) % self.p
        
        x3 = (s * s - 2 * P.x) % self.p
        y3 = (s * (P.x - x3) - P.y) % self.p
        
        return Point(x3, y3)
    
    def point_multiply(self, k: int, P: Point) -> Point:
        """标量乘法 k*P"""
        if k == 0:
            return self.O
        if k == 1:
            return P
        
        result = self.O
        addend = P
        
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_double(addend)
            k >>= 1
        
        return result


class SM2Basic:
    """SM2基础实现"""
    
    def __init__(self):
        self.curve = SM2Curve()
    
    def generate_keypair(self) -> Tuple[int, Point]:
        """生成密钥对
        Returns:
            (private_key, public_key)
        """
        # 生成私钥
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        
        # 计算公钥
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        
        return private_key, public_key
    
    def sm3_hash(self, data: bytes) -> bytes:
        """SM3哈希函数 (简化版本，实际应该使用标准SM3)"""
        # 这里使用SHA256作为替代，在实际应用中应该使用SM3
        return hashlib.sha256(data).digest()
    
    def za_value(self, user_id: bytes, public_key: Point) -> bytes:
        """计算用户身份标识的杂凑值Za"""
        # 用户身份标识长度
        id_len = len(user_id) * 8
        id_len_bytes = struct.pack('>H', id_len)
        
        # 椭圆曲线参数
        a_bytes = self.curve.a.to_bytes(32, 'big')
        b_bytes = self.curve.b.to_bytes(32, 'big')
        gx_bytes = self.curve.Gx.to_bytes(32, 'big')
        gy_bytes = self.curve.Gy.to_bytes(32, 'big')
        
        # 公钥坐标
        px_bytes = public_key.x.to_bytes(32, 'big')
        py_bytes = public_key.y.to_bytes(32, 'big')
        
        # 拼接所有数据
        za_data = (id_len_bytes + user_id + a_bytes + b_bytes + 
                   gx_bytes + gy_bytes + px_bytes + py_bytes)
        
        return self.sm3_hash(za_data)
    
    def sign(self, private_key: int, message: bytes, user_id: bytes = b'1234567812345678') -> Tuple[int, int]:
        """数字签名
        Args:
            private_key: 私钥
            message: 待签名消息
            user_id: 用户身份标识
        Returns:
            (r, s): 签名值
        """
        # 计算公钥
        public_key = self.curve.point_multiply(private_key, self.curve.G)
        
        # 计算Za值
        za = self.za_value(user_id, public_key)
        
        # 计算消息摘要
        M_prime = za + message
        e = int.from_bytes(self.sm3_hash(M_prime), 'big')
        
        while True:
            # 生成随机数k
            k = secrets.randbelow(self.curve.n - 1) + 1
            
            # 计算椭圆曲线点(x1, y1) = [k]G
            point = self.curve.point_multiply(k, self.curve.G)
            
            # 计算r
            r = (e + point.x) % self.curve.n
            if r == 0 or r + k == self.curve.n:
                continue
            
            # 计算s
            d_inv = pow(1 + private_key, -1, self.curve.n)
            s = (d_inv * (k - r * private_key)) % self.curve.n
            if s == 0:
                continue
            
            return r, s
    
    def verify(self, public_key: Point, message: bytes, signature: Tuple[int, int], 
               user_id: bytes = b'1234567812345678') -> bool:
        """验证数字签名
        Args:
            public_key: 公钥
            message: 原始消息
            signature: 签名(r, s)
            user_id: 用户身份标识
        Returns:
            验证结果
        """
        r, s = signature
        
        # 检查签名格式
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False
        
        # 计算Za值
        za = self.za_value(user_id, public_key)
        
        # 计算消息摘要
        M_prime = za + message
        e = int.from_bytes(self.sm3_hash(M_prime), 'big')
        
        # 计算t
        t = (r + s) % self.curve.n
        if t == 0:
            return False
        
        # 计算椭圆曲线点(x1', y1') = [s]G + [t]PA
        point1 = self.curve.point_multiply(s, self.curve.G)
        point2 = self.curve.point_multiply(t, public_key)
        point = self.curve.point_add(point1, point2)
        
        # 计算R
        R = (e + point.x) % self.curve.n
        
        return R == r


class SM2Optimized(SM2Basic):
    """SM2优化实现"""
    
    def __init__(self):
        super().__init__()
        self._precomputed_points = {}
    
    def precompute_points(self, point: Point, max_bits: int = 256):
        """预计算点的倍数以加速标量乘法"""
        key = (point.x, point.y)
        if key in self._precomputed_points:
            return
        
        precomputed = [self.curve.O] * max_bits
        current = point
        
        for i in range(max_bits):
            precomputed[i] = current
            current = self.curve.point_double(current)
        
        self._precomputed_points[key] = precomputed
    
    def optimized_point_multiply(self, k: int, P: Point) -> Point:
        """优化的标量乘法"""
        key = (P.x, P.y)
        
        # 如果没有预计算，使用普通方法
        if key not in self._precomputed_points:
            return self.curve.point_multiply(k, P)
        
        precomputed = self._precomputed_points[key]
        result = self.curve.O
        
        bit_index = 0
        while k > 0:
            if k & 1:
                if bit_index < len(precomputed):
                    result = self.curve.point_add(result, precomputed[bit_index])
                else:
                    # 超出预计算范围，使用普通方法
                    remaining = k << bit_index
                    remaining_point = self.curve.point_multiply(remaining, P)
                    result = self.curve.point_add(result, remaining_point)
                    break
            k >>= 1
            bit_index += 1
        
        return result
    
    def generate_keypair(self) -> Tuple[int, Point]:
        """优化的密钥对生成"""
        # 预计算基点G的倍数
        self.precompute_points(self.curve.G)
        
        # 生成私钥
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        
        # 使用优化的点乘计算公钥
        public_key = self.optimized_point_multiply(private_key, self.curve.G)
        
        return private_key, public_key
    
    def sign(self, private_key: int, message: bytes, user_id: bytes = b'1234567812345678') -> Tuple[int, int]:
        """优化的数字签名"""
        # 预计算基点G的倍数
        self.precompute_points(self.curve.G)
        
        # 计算公钥（使用优化的点乘）
        public_key = self.optimized_point_multiply(private_key, self.curve.G)
        
        # 计算Za值
        za = self.za_value(user_id, public_key)
        
        # 计算消息摘要
        M_prime = za + message
        e = int.from_bytes(self.sm3_hash(M_prime), 'big')
        
        while True:
            # 生成随机数k
            k = secrets.randbelow(self.curve.n - 1) + 1
            
            # 使用优化的点乘计算椭圆曲线点
            point = self.optimized_point_multiply(k, self.curve.G)
            
            # 计算r
            r = (e + point.x) % self.curve.n
            if r == 0 or r + k == self.curve.n:
                continue
            
            # 计算s
            d_inv = pow(1 + private_key, -1, self.curve.n)
            s = (d_inv * (k - r * private_key)) % self.curve.n
            if s == 0:
                continue
            
            return r, s
    
    def verify(self, public_key: Point, message: bytes, signature: Tuple[int, int], 
               user_id: bytes = b'1234567812345678') -> bool:
        """优化的签名验证"""
        r, s = signature
        
        # 检查签名格式
        if not (1 <= r < self.curve.n and 1 <= s < self.curve.n):
            return False
        
        # 预计算基点G和公钥的倍数
        self.precompute_points(self.curve.G)
        self.precompute_points(public_key)
        
        # 计算Za值
        za = self.za_value(user_id, public_key)
        
        # 计算消息摘要
        M_prime = za + message
        e = int.from_bytes(self.sm3_hash(M_prime), 'big')
        
        # 计算t
        t = (r + s) % self.curve.n
        if t == 0:
            return False
        
        # 使用优化的点乘计算椭圆曲线点
        point1 = self.optimized_point_multiply(s, self.curve.G)
        point2 = self.optimized_point_multiply(t, public_key)
        point = self.curve.point_add(point1, point2)
        
        # 计算R
        R = (e + point.x) % self.curve.n
        
        return R == r


def demo():
    """SM2算法演示"""
    print("=== SM2椭圆曲线数字签名算法演示 ===")
    
    # 测试基础实现
    print("\n1. 基础实现测试")
    sm2_basic = SM2Basic()
    
    # 生成密钥对
    private_key, public_key = sm2_basic.generate_keypair()
    print(f"私钥: {private_key:064x}")
    print(f"公钥: {public_key}")
    
    # 签名
    message = b"Hello SM2!"
    signature = sm2_basic.sign(private_key, message)
    print(f"消息: {message}")
    print(f"签名: r={signature[0]:064x}, s={signature[1]:064x}")
    
    # 验证
    is_valid = sm2_basic.verify(public_key, message, signature)
    print(f"验证结果: {'✅ 有效' if is_valid else '❌ 无效'}")
    
    # 测试优化实现
    print("\n2. 优化实现测试")
    sm2_opt = SM2Optimized()
    
    # 生成密钥对
    private_key_opt, public_key_opt = sm2_opt.generate_keypair()
    print(f"私钥: {private_key_opt:064x}")
    print(f"公钥: {public_key_opt}")
    
    # 签名
    signature_opt = sm2_opt.sign(private_key_opt, message)
    print(f"签名: r={signature_opt[0]:064x}, s={signature_opt[1]:064x}")
    
    # 验证
    is_valid_opt = sm2_opt.verify(public_key_opt, message, signature_opt)
    print(f"验证结果: {'✅ 有效' if is_valid_opt else '❌ 无效'}")
    
    # 交叉验证（错误的密钥）
    print("\n3. 交叉验证测试")
    is_cross_valid = sm2_basic.verify(public_key_opt, message, signature)
    print(f"用错误公钥验证: {'✅ 有效' if is_cross_valid else '❌ 无效'}")


if __name__ == "__main__":
    demo()

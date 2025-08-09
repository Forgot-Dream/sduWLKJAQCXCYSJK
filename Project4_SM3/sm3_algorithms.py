#!/usr/bin/env python3
"""
SM3算法实现模块

包含基础实现和优化实现，支持长度扩展攻击演示
"""

import struct
import time
from typing import List, Tuple, Optional
from abc import ABC, abstractmethod


class SM3Base(ABC):
    """SM3算法基类"""
    
    # SM3常量
    IV = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    ]
    
    T_0_15 = 0x79CC4519
    T_16_63 = 0x7A879D8A
    
    @abstractmethod
    def hash(self, message: bytes) -> str:
        """计算SM3哈希值"""
        pass
    
    @staticmethod
    def rotate_left(value: int, bits: int) -> int:
        """循环左移"""
        value &= 0xFFFFFFFF
        return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF
    
    @staticmethod
    def ff(x: int, y: int, z: int, j: int) -> int:
        """布尔函数FF"""
        if j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | (x & z) | (y & z)
    
    @staticmethod
    def gg(x: int, y: int, z: int, j: int) -> int:
        """布尔函数GG"""
        if j <= 15:
            return x ^ y ^ z
        else:
            return (x & y) | (~x & z)
    
    @staticmethod
    def p0(x: int) -> int:
        """置换函数P0"""
        return x ^ SM3Base.rotate_left(x, 9) ^ SM3Base.rotate_left(x, 17)
    
    @staticmethod
    def p1(x: int) -> int:
        """置换函数P1"""
        return x ^ SM3Base.rotate_left(x, 15) ^ SM3Base.rotate_left(x, 23)
    
    @staticmethod
    def t(j: int) -> int:
        """常数T_j"""
        if j <= 15:
            return SM3Base.T_0_15
        else:
            return SM3Base.T_16_63
    
    @staticmethod
    def padding(message: bytes) -> bytes:
        """消息填充"""
        msg_len = len(message)
        bit_len = msg_len * 8
        
        # 添加0x80
        padded = message + b'\x80'
        
        # 添加0填充，使得长度≡56 (mod 64)
        while len(padded) % 64 != 56:
            padded += b'\x00'
        
        # 添加长度（大端序）
        padded += struct.pack('>Q', bit_len)
        
        return padded
    
    @staticmethod
    def message_expansion(b: List[int]) -> List[int]:
        """消息扩展"""
        w = b.copy()
        
        for j in range(16, 68):
            temp = w[j-16] ^ w[j-9] ^ SM3Base.rotate_left(w[j-3], 15)
            w.append(SM3Base.p1(temp) ^ SM3Base.rotate_left(w[j-13], 7) ^ w[j-6])
        
        return w
    
    @staticmethod
    def compress(v: List[int], b: List[int]) -> List[int]:
        """压缩函数"""
        w = SM3Base.message_expansion(b)
        
        # 计算W'
        w_prime = [w[j] ^ w[j + 4] for j in range(64)]
        
        # 初始化工作变量
        a, b_reg, c, d = v[0], v[1], v[2], v[3]
        e, f, g, h = v[4], v[5], v[6], v[7]
        
        # 64轮迭代
        for j in range(64):
            ss1 = SM3Base.rotate_left(
                (SM3Base.rotate_left(a, 12) + e + SM3Base.rotate_left(SM3Base.t(j), j % 32)) & 0xFFFFFFFF, 
                7
            )
            ss2 = ss1 ^ SM3Base.rotate_left(a, 12)
            
            tt1 = (SM3Base.ff(a, b_reg, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (SM3Base.gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            
            d = c
            c = SM3Base.rotate_left(b_reg, 9)
            b_reg = a
            a = tt1
            h = g
            g = SM3Base.rotate_left(f, 19)
            f = e
            e = SM3Base.p0(tt2)
        
        return [
            (a ^ v[0]) & 0xFFFFFFFF, (b_reg ^ v[1]) & 0xFFFFFFFF,
            (c ^ v[2]) & 0xFFFFFFFF, (d ^ v[3]) & 0xFFFFFFFF,
            (e ^ v[4]) & 0xFFFFFFFF, (f ^ v[5]) & 0xFFFFFFFF,
            (g ^ v[6]) & 0xFFFFFFFF, (h ^ v[7]) & 0xFFFFFFFF
        ]


class SM3Basic(SM3Base):
    """SM3基础实现"""
    
    def hash(self, message: bytes) -> str:
        """计算SM3哈希值"""
        return self._hash_internal(message)
    
    def _hash_internal(self, message: bytes, initial_value: Optional[List[int]] = None) -> str:
        """内部哈希函数，支持自定义初始值"""
        if initial_value is None:
            initial_value = self.IV.copy()
        
        padded = self.padding(message)
        v = initial_value.copy()
        
        # 处理每64字节块
        for i in range(0, len(padded), 64):
            block = padded[i:i+64]
            b = list(struct.unpack('>16I', block))
            v = self.compress(v, b)
        
        # 转换为十六进制字符串
        return ''.join(f'{word:08x}' for word in v)
    
    def get_intermediate_state(self, message: bytes) -> List[int]:
        """获取中间状态（用于长度扩展攻击）"""
        padded = self.padding(message)
        v = self.IV.copy()
        
        for i in range(0, len(padded), 64):
            block = padded[i:i+64]
            b = list(struct.unpack('>16I', block))
            v = self.compress(v, b)
        
        return v
    
    def get_state_from_hash(self, hash_hex: str) -> List[int]:
        """从哈希值中提取状态（用于长度扩展攻击）"""
        # 将十六进制字符串转换为8个32位整数
        state = []
        for i in range(0, len(hash_hex), 8):
            state.append(int(hash_hex[i:i+8], 16))
        return state
    
    def compute_padding_for_length(self, length: int) -> bytes:
        """为指定长度计算填充"""
        bit_len = length * 8
        
        # 添加0x80
        padded = b'\x80'
        
        # 计算需要多少0字节
        current_len = length + 1  # 包括0x80字节
        target_len = ((current_len + 8 + 63) // 64) * 64
        padding_zeros = target_len - current_len - 8
        
        padded += b'\x00' * padding_zeros
        padded += struct.pack('>Q', bit_len)
        
        return padded[1:]  # 不包括0x80，因为这在原始消息之后已经添加了
    
    def length_extension_attack(self, original_hash: str, known_message_length: int, 
                               append_data: bytes) -> Tuple[str, bytes]:
        """
        长度扩展攻击演示
        
        参数:
        - original_hash: 原始消息的哈希值 SM3(secret || message)
        - known_message_length: 已知的消息总长度（secret + message）
        - append_data: 要附加的数据
        
        返回:
        - 伪造的哈希值和完整的消息后缀（包括填充和附加数据）
        """
        # 1. 从哈希值提取内部状态
        state = self.get_state_from_hash(original_hash)
        
        # 2. 计算原始消息经过填充后的总长度
        bit_len = known_message_length * 8
        original_padded_length = known_message_length + 1  # +1 for 0x80
        
        # 计算需要多少0字节填充
        while (original_padded_length + 8) % 64 != 0:
            original_padded_length += 1
        original_padded_length += 8  # 添加长度字段
        
        # 3. 构造原始消息的填充部分（这将成为伪造消息的一部分）
        padding_length = original_padded_length - known_message_length
        original_padding = b'\x80'
        zero_padding_count = padding_length - 9  # -1 for 0x80, -8 for length
        original_padding += b'\x00' * zero_padding_count
        original_padding += struct.pack('>Q', bit_len)
        
        # 4. 现在从这个状态开始，对新的数据（附加数据）进行哈希
        # 新的总长度 = 原始填充后长度 + 附加数据长度
        new_total_length = original_padded_length + len(append_data)
        
        # 5. 对附加数据进行标准的SM3填充
        new_bit_len = new_total_length * 8
        new_message = append_data + b'\x80'
        
        # 计算新的填充
        current_len = len(new_message)
        while (current_len + 8) % 64 != 0:
            new_message += b'\x00'
            current_len += 1
        new_message += struct.pack('>Q', new_bit_len)
        
        # 6. 使用提取的状态继续计算哈希
        v = state.copy()
        
        # 处理附加数据的每个64字节块
        for i in range(0, len(new_message), 64):
            block = new_message[i:i+64]
            b = list(struct.unpack('>16I', block))
            v = self.compress(v, b)
        
        # 7. 构造完整的消息后缀
        message_suffix = original_padding + append_data
        
        return (''.join(f'{word:08x}' for word in v), message_suffix)


class SM3Optimized(SM3Base):
    """SM3优化实现"""
    
    def __init__(self):
        # 预计算T值表
        self.t_table = self._create_t_table()
    
    def _create_t_table(self) -> List[int]:
        """创建预计算的T值表"""
        table = []
        for j in range(64):
            if j <= 15:
                table.append(self.rotate_left(self.T_0_15, j % 32))
            else:
                table.append(self.rotate_left(self.T_16_63, j % 32))
        return table
    
    def hash(self, message: bytes) -> str:
        """计算SM3哈希值（优化版本）"""
        padded = self.padding(message)
        v = self.IV.copy()
        
        # 处理每64字节块
        for i in range(0, len(padded), 64):
            block = padded[i:i+64]
            b = list(struct.unpack('>16I', block))
            v = self._optimized_compress(v, b)
        
        return ''.join(f'{word:08x}' for word in v)
    
    def _optimized_compress(self, v: List[int], b: List[int]) -> List[int]:
        """优化的压缩函数"""
        w = self._optimized_message_expansion(b)
        
        # 预计算W'
        w_prime = [w[j] ^ w[j + 4] for j in range(64)]
        
        # 初始化工作变量
        a, b_reg, c, d = v[0], v[1], v[2], v[3]
        e, f, g, h = v[4], v[5], v[6], v[7]
        
        # 64轮迭代 - 使用预计算的T值
        for j in range(64):
            rot_a_12 = self.rotate_left(a, 12)
            ss1 = self.rotate_left((rot_a_12 + e + self.t_table[j]) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ rot_a_12
            
            tt1 = (self.ff(a, b_reg, c, j) + d + ss2 + w_prime[j]) & 0xFFFFFFFF
            tt2 = (self.gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
            
            d = c
            c = self.rotate_left(b_reg, 9)
            b_reg = a
            a = tt1
            h = g
            g = self.rotate_left(f, 19)
            f = e
            e = self.p0(tt2)
        
        return [
            (a ^ v[0]) & 0xFFFFFFFF, (b_reg ^ v[1]) & 0xFFFFFFFF,
            (c ^ v[2]) & 0xFFFFFFFF, (d ^ v[3]) & 0xFFFFFFFF,
            (e ^ v[4]) & 0xFFFFFFFF, (f ^ v[5]) & 0xFFFFFFFF,
            (g ^ v[6]) & 0xFFFFFFFF, (h ^ v[7]) & 0xFFFFFFFF
        ]
    
    def _optimized_message_expansion(self, b: List[int]) -> List[int]:
        """优化的消息扩展"""
        w = b.copy()
        
        # 循环展开优化
        for j in range(16, 68):
            temp = w[j-16] ^ w[j-9] ^ self.rotate_left(w[j-3], 15)
            w.append(self.p1(temp) ^ self.rotate_left(w[j-13], 7) ^ w[j-6])
        
        return w


class SM3Benchmark:
    """SM3性能基准测试"""
    
    def __init__(self):
        self.basic_sm3 = SM3Basic()
        self.optimized_sm3 = SM3Optimized()
    
    def benchmark_basic(self, data: bytes, iterations: int = 1000) -> dict:
        """基础版本性能测试"""
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            self.basic_sm3.hash(data)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        return {
            'total_time': total_time,
            'average_time': total_time / iterations,
            'throughput': len(data) * iterations / total_time / (1024 * 1024),  # MB/s
            'hashes_per_second': iterations / total_time
        }
    
    def benchmark_optimized(self, data: bytes, iterations: int = 1000) -> dict:
        """优化版本性能测试"""
        start_time = time.perf_counter()
        
        for _ in range(iterations):
            self.optimized_sm3.hash(data)
        
        end_time = time.perf_counter()
        total_time = end_time - start_time
        
        return {
            'total_time': total_time,
            'average_time': total_time / iterations,
            'throughput': len(data) * iterations / total_time / (1024 * 1024),  # MB/s
            'hashes_per_second': iterations / total_time
        }
    
    def compare_implementations(self, data: bytes, iterations: int = 1000) -> dict:
        """对比两种实现的性能"""
        basic_result = self.benchmark_basic(data, iterations)
        optimized_result = self.benchmark_optimized(data, iterations)
        
        speedup = basic_result['total_time'] / optimized_result['total_time']
        throughput_improvement = (optimized_result['throughput'] / basic_result['throughput'] - 1) * 100
        
        return {
            'basic_result': basic_result,
            'optimized_result': optimized_result,
            'speedup_factor': speedup,
            'throughput_improvement': throughput_improvement
        }
    
    def print_benchmark_result(self, result: dict, name: str):
        """打印基准测试结果"""
        print(f"\n{name} 性能测试结果:")
        print(f"总时间: {result['total_time']:.4f} 秒")
        print(f"平均时间: {result['average_time']*1000:.4f} 毫秒")
        print(f"吞吐量: {result['throughput']:.2f} MB/s")
        print(f"哈希速率: {result['hashes_per_second']:.0f} 哈希/秒")
    
    def print_comparison_result(self, result: dict):
        """打印对比结果"""
        print("\n=== SM3性能对比结果 ===")
        self.print_benchmark_result(result['basic_result'], "基础实现")
        self.print_benchmark_result(result['optimized_result'], "优化实现")
        
        print(f"\n性能提升:")
        print(f"速度提升: {result['speedup_factor']:.2f}x")
        print(f"吞吐量提升: {result['throughput_improvement']:.1f}%")


def test_standard_vectors():
    """测试标准测试向量"""
    print("=== SM3标准测试向量验证 ===")
    
    sm3_basic = SM3Basic()
    sm3_optimized = SM3Optimized()
    
    test_vectors = [
        (b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
        (b"a", "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"),
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"message digest", "c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77"),
        (b"abcdefghijklmnopqrstuvwxyz", "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595")
    ]
    
    for i, (message, expected) in enumerate(test_vectors):
        basic_result = sm3_basic.hash(message)
        optimized_result = sm3_optimized.hash(message)
        
        print(f"\n测试向量 {i+1}:")
        print(f"输入: {message}")
        print(f"期望: {expected}")
        print(f"基础: {basic_result} {'✓' if basic_result == expected else '✗'}")
        print(f"优化: {optimized_result} {'✓' if optimized_result == expected else '✗'}")
        print(f"一致: {'✓' if basic_result == optimized_result else '✗'}")


if __name__ == "__main__":
    # 运行标准测试向量验证
    test_standard_vectors()
    
    # 性能基准测试
    print("\n" + "="*50)
    benchmark = SM3Benchmark()
    
    # 测试不同大小的数据
    test_sizes = [64, 256, 1024, 4096, 16384]
    
    for size in test_sizes:
        print(f"\n测试数据大小: {size} 字节")
        test_data = b'a' * size
        iterations = max(100, 100000 // size)
        
        comparison = benchmark.compare_implementations(test_data, iterations)
        
        print(f"迭代次数: {iterations}")
        print(f"基础版本: {comparison['basic_result']['throughput']:.2f} MB/s")
        print(f"优化版本: {comparison['optimized_result']['throughput']:.2f} MB/s")
        print(f"性能提升: {comparison['speedup_factor']:.2f}x")

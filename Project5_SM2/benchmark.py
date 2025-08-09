#!/usr/bin/env python3
"""
SM2算法性能基准测试
对比基础实现和优化实现的性能差异
"""

import time
import statistics
from typing import List, Dict, Tuple
from sm2_algorithms import SM2Basic, SM2Optimized
import matplotlib.pyplot as plt
import json


class SM2Benchmark:
    """SM2性能基准测试类"""
    
    def __init__(self):
        self.sm2_basic = SM2Basic()
        self.sm2_optimized = SM2Optimized()
        self.results = {}
    
    def benchmark_keypair_generation(self, iterations: int = 100) -> Dict:
        """基准测试密钥对生成"""
        print(f"基准测试: 密钥对生成 (迭代次数: {iterations})")
        
        # 基础版本
        basic_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.sm2_basic.generate_keypair()
            basic_times.append(time.time() - start_time)
        
        # 优化版本
        optimized_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.sm2_optimized.generate_keypair()
            optimized_times.append(time.time() - start_time)
        
        basic_avg = statistics.mean(basic_times)
        optimized_avg = statistics.mean(optimized_times)
        speedup = basic_avg / optimized_avg if optimized_avg > 0 else 0
        
        result = {
            'basic_avg': basic_avg,
            'optimized_avg': optimized_avg,
            'speedup': speedup,
            'basic_std': statistics.stdev(basic_times),
            'optimized_std': statistics.stdev(optimized_times)
        }
        
        print(f"  基础版本平均时间: {basic_avg*1000:.2f} ms")
        print(f"  优化版本平均时间: {optimized_avg*1000:.2f} ms")
        print(f"  性能提升: {speedup:.2f}x")
        
        return result
    
    def benchmark_signing(self, iterations: int = 50) -> Dict:
        """基准测试数字签名"""
        print(f"基准测试: 数字签名 (迭代次数: {iterations})")
        
        # 准备测试数据
        message = b"Benchmark message for SM2 signing performance test"
        
        # 生成密钥对
        basic_private, basic_public = self.sm2_basic.generate_keypair()
        opt_private, opt_public = self.sm2_optimized.generate_keypair()
        
        # 基础版本签名测试
        basic_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.sm2_basic.sign(basic_private, message)
            basic_times.append(time.time() - start_time)
        
        # 优化版本签名测试
        optimized_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.sm2_optimized.sign(opt_private, message)
            optimized_times.append(time.time() - start_time)
        
        basic_avg = statistics.mean(basic_times)
        optimized_avg = statistics.mean(optimized_times)
        speedup = basic_avg / optimized_avg if optimized_avg > 0 else 0
        
        result = {
            'basic_avg': basic_avg,
            'optimized_avg': optimized_avg,
            'speedup': speedup,
            'basic_std': statistics.stdev(basic_times),
            'optimized_std': statistics.stdev(optimized_times)
        }
        
        print(f"  基础版本平均时间: {basic_avg*1000:.2f} ms")
        print(f"  优化版本平均时间: {optimized_avg*1000:.2f} ms")
        print(f"  性能提升: {speedup:.2f}x")
        
        return result
    
    def benchmark_verification(self, iterations: int = 50) -> Dict:
        """基准测试签名验证"""
        print(f"基准测试: 签名验证 (迭代次数: {iterations})")
        
        # 准备测试数据
        message = b"Benchmark message for SM2 verification performance test"
        
        # 生成密钥对和签名
        basic_private, basic_public = self.sm2_basic.generate_keypair()
        basic_signature = self.sm2_basic.sign(basic_private, message)
        
        opt_private, opt_public = self.sm2_optimized.generate_keypair()
        opt_signature = self.sm2_optimized.sign(opt_private, message)
        
        # 基础版本验证测试
        basic_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.sm2_basic.verify(basic_public, message, basic_signature)
            basic_times.append(time.time() - start_time)
        
        # 优化版本验证测试
        optimized_times = []
        for _ in range(iterations):
            start_time = time.time()
            self.sm2_optimized.verify(opt_public, message, opt_signature)
            optimized_times.append(time.time() - start_time)
        
        basic_avg = statistics.mean(basic_times)
        optimized_avg = statistics.mean(optimized_times)
        speedup = basic_avg / optimized_avg if optimized_avg > 0 else 0
        
        result = {
            'basic_avg': basic_avg,
            'optimized_avg': optimized_avg,
            'speedup': speedup,
            'basic_std': statistics.stdev(basic_times),
            'optimized_std': statistics.stdev(optimized_times)
        }
        
        print(f"  基础版本平均时间: {basic_avg*1000:.2f} ms")
        print(f"  优化版本平均时间: {optimized_avg*1000:.2f} ms")
        print(f"  性能提升: {speedup:.2f}x")
        
        return result
    
    def benchmark_scalar_multiplication(self, iterations: int = 20) -> Dict:
        """基准测试椭圆曲线标量乘法"""
        print(f"基准测试: 椭圆曲线标量乘法 (迭代次数: {iterations})")
        
        # 准备测试数据
        test_scalars = [
            0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0,
            0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
            0x9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA
        ]
        
        basic_curve = self.sm2_basic.curve
        opt_curve = self.sm2_optimized.curve
        
        # 基础版本测试
        basic_times = []
        for scalar in test_scalars:
            for _ in range(iterations):
                start_time = time.time()
                basic_curve.point_multiply(scalar, basic_curve.G)
                basic_times.append(time.time() - start_time)
        
        # 优化版本测试（预先计算）
        self.sm2_optimized.precompute_points(opt_curve.G)
        optimized_times = []
        for scalar in test_scalars:
            for _ in range(iterations):
                start_time = time.time()
                self.sm2_optimized.optimized_point_multiply(scalar, opt_curve.G)
                optimized_times.append(time.time() - start_time)
        
        basic_avg = statistics.mean(basic_times)
        optimized_avg = statistics.mean(optimized_times)
        speedup = basic_avg / optimized_avg if optimized_avg > 0 else 0
        
        result = {
            'basic_avg': basic_avg,
            'optimized_avg': optimized_avg,
            'speedup': speedup,
            'basic_std': statistics.stdev(basic_times),
            'optimized_std': statistics.stdev(optimized_times)
        }
        
        print(f"  基础版本平均时间: {basic_avg*1000:.2f} ms")
        print(f"  优化版本平均时间: {optimized_avg*1000:.2f} ms")
        print(f"  性能提升: {speedup:.2f}x")
        
        return result
    
    def run_comprehensive_benchmark(self) -> Dict:
        """运行综合性能基准测试"""
        print("🚀 SM2算法综合性能基准测试")
        print("=" * 60)
        
        results = {}
        
        # 1. 密钥对生成
        results['keypair_generation'] = self.benchmark_keypair_generation(100)
        print()
        
        # 2. 数字签名
        results['signing'] = self.benchmark_signing(50)
        print()
        
        # 3. 签名验证
        results['verification'] = self.benchmark_verification(50)
        print()
        
        # 4. 椭圆曲线标量乘法
        results['scalar_multiplication'] = self.benchmark_scalar_multiplication(20)
        print()
        
        # 保存结果
        self.results = results
        
        # 打印总结
        self.print_summary()
        
        return results
    
    def print_summary(self):
        """打印性能测试总结"""
        print("=" * 60)
        print("📊 性能测试总结")
        print("=" * 60)
        
        operations = ['keypair_generation', 'signing', 'verification', 'scalar_multiplication']
        operation_names = ['密钥生成', '数字签名', '签名验证', '标量乘法']
        
        print(f"{'操作':<12} {'基础版本(ms)':<15} {'优化版本(ms)':<15} {'性能提升':<10}")
        print("-" * 60)
        
        total_speedup = 1.0
        count = 0
        
        for op, name in zip(operations, operation_names):
            if op in self.results:
                basic_time = self.results[op]['basic_avg'] * 1000
                opt_time = self.results[op]['optimized_avg'] * 1000
                speedup = self.results[op]['speedup']
                
                print(f"{name:<12} {basic_time:<15.2f} {opt_time:<15.2f} {speedup:<10.2f}x")
                
                total_speedup *= speedup
                count += 1
        
        if count > 0:
            geometric_mean_speedup = total_speedup ** (1.0 / count)
            print("-" * 60)
            print(f"几何平均性能提升: {geometric_mean_speedup:.2f}x")
    
    def save_results(self, filename: str = "sm2_benchmark_results.json"):
        """保存测试结果到文件"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"结果已保存到: {filename}")
    
    def plot_results(self, save_plot: bool = True):
        """绘制性能对比图表"""
        try:
            operations = ['keypair_generation', 'signing', 'verification', 'scalar_multiplication']
            operation_names = ['密钥生成', '数字签名', '签名验证', '标量乘法']
            
            basic_times = []
            opt_times = []
            speedups = []
            
            for op in operations:
                if op in self.results:
                    basic_times.append(self.results[op]['basic_avg'] * 1000)
                    opt_times.append(self.results[op]['optimized_avg'] * 1000)
                    speedups.append(self.results[op]['speedup'])
            
            # 创建子图
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # 子图1: 执行时间对比
            x = range(len(operation_names))
            width = 0.35
            
            ax1.bar([i - width/2 for i in x], basic_times, width, label='基础版本', alpha=0.8)
            ax1.bar([i + width/2 for i in x], opt_times, width, label='优化版本', alpha=0.8)
            
            ax1.set_xlabel('操作类型')
            ax1.set_ylabel('执行时间 (ms)')
            ax1.set_title('SM2算法性能对比')
            ax1.set_xticks(x)
            ax1.set_xticklabels(operation_names)
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # 子图2: 性能提升倍数
            ax2.bar(operation_names, speedups, alpha=0.8, color='green')
            ax2.set_xlabel('操作类型')
            ax2.set_ylabel('性能提升倍数')
            ax2.set_title('优化版本性能提升')
            ax2.grid(True, alpha=0.3)
            
            # 在柱状图上显示数值
            for i, v in enumerate(speedups):
                ax2.text(i, v + 0.01, f'{v:.2f}x', ha='center', va='bottom')
            
            plt.tight_layout()
            
            if save_plot:
                plt.savefig('sm2_performance_comparison.png', dpi=300, bbox_inches='tight')
                print("性能对比图表已保存到: sm2_performance_comparison.png")
            
            plt.show()
            
        except ImportError:
            print("警告: matplotlib未安装，无法生成图表")
        except Exception as e:
            print(f"绘图时出错: {e}")


def memory_usage_test():
    """内存使用情况测试"""
    print("🧠 内存使用情况测试")
    print("=" * 40)
    
    try:
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # 基础版本内存测试
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        sm2_basic = SM2Basic()
        for _ in range(100):
            sm2_basic.generate_keypair()
        
        basic_memory = process.memory_info().rss / 1024 / 1024  # MB
        basic_usage = basic_memory - initial_memory
        
        # 优化版本内存测试
        sm2_opt = SM2Optimized()
        for _ in range(100):
            sm2_opt.generate_keypair()
        
        optimized_memory = process.memory_info().rss / 1024 / 1024  # MB
        optimized_usage = optimized_memory - basic_memory
        
        print(f"基础版本内存使用: {basic_usage:.2f} MB")
        print(f"优化版本额外内存: {optimized_usage:.2f} MB")
        print(f"总内存使用: {optimized_memory:.2f} MB")
        
    except ImportError:
        print("警告: psutil未安装，无法进行内存测试")


def main():
    """主函数"""
    benchmark = SM2Benchmark()
    
    # 运行综合性能测试
    results = benchmark.run_comprehensive_benchmark()
    
    # 内存使用测试
    memory_usage_test()
    
    # 保存结果
    benchmark.save_results()
    
    # 绘制图表
    benchmark.plot_results()
    
    print("\n✅ 基准测试完成！")


if __name__ == "__main__":
    main()

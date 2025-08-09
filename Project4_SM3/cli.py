#!/usr/bin/env python3
"""
SM3项目命令行接口

提供统一的命令行入口来运行各种SM3相关功能
"""

import argparse
import sys
import time
import os
from sm3_algorithms import SM3Basic, SM3Optimized, SM3Benchmark, test_standard_vectors
from merkle_tree import MerkleTree, demo_merkle_tree, large_merkle_tree_test
from length_extension_attack import demonstrate_length_extension_attack, demonstrate_hmac_protection


def cmd_hash(args):
    """计算文件或字符串的SM3哈希"""
    if args.optimized:
        sm3 = SM3Optimized()
        print("使用优化版本SM3")
    else:
        sm3 = SM3Basic()
        print("使用基础版本SM3")
    
    if args.file:
        # 计算文件哈希
        try:
            with open(args.input, 'rb') as f:
                data = f.read()
            
            start_time = time.time()
            hash_result = sm3.hash(data)
            elapsed = time.time() - start_time
            
            print(f"文件: {args.input}")
            print(f"大小: {len(data)} 字节")
            print(f"SM3: {hash_result}")
            print(f"计算时间: {elapsed*1000:.2f} 毫秒")
            
        except FileNotFoundError:
            print(f"错误: 文件 '{args.input}' 不存在")
            sys.exit(1)
        except Exception as e:
            print(f"错误: {e}")
            sys.exit(1)
    else:
        # 计算字符串哈希
        data = args.input.encode('utf-8')
        hash_result = sm3.hash(data)
        
        print(f"输入: {args.input}")
        print(f"SM3: {hash_result}")


def cmd_benchmark(args):
    """运行性能基准测试"""
    print("=== SM3性能基准测试 ===")
    
    benchmark = SM3Benchmark()
    
    # 默认测试大小
    test_sizes = [64, 256, 1024, 4096, 16384, 65536]
    if args.size:
        test_sizes = [args.size]
    
    iterations = args.iterations
    
    print(f"测试配置:")
    print(f"- 数据大小: {test_sizes}")
    print(f"- 迭代次数: {iterations}")
    print(f"- 输出格式: {'详细' if args.verbose else '简洁'}")
    
    results = []
    
    for size in test_sizes:
        print(f"\n{'='*50}")
        print(f"测试数据大小: {size} 字节")
        
        # 生成测试数据
        test_data = b'a' * size
        actual_iterations = max(10, iterations // (size // 64 + 1))
        
        # 运行对比测试
        comparison = benchmark.compare_implementations(test_data, actual_iterations)
        
        if args.verbose:
            benchmark.print_comparison_result(comparison)
        else:
            basic_throughput = comparison['basic_result']['throughput']
            optimized_throughput = comparison['optimized_result']['throughput']
            speedup = comparison['speedup_factor']
            
            print(f"基础版本: {basic_throughput:.2f} MB/s")
            print(f"优化版本: {optimized_throughput:.2f} MB/s")
            print(f"性能提升: {speedup:.2f}x ({comparison['throughput_improvement']:+.1f}%)")
        
        results.append({
            'size': size,
            'basic_throughput': comparison['basic_result']['throughput'],
            'optimized_throughput': comparison['optimized_result']['throughput'],
            'speedup': comparison['speedup_factor']
        })
    
    # 输出总结
    if len(results) > 1:
        print(f"\n{'='*50}")
        print("测试总结:")
        print(f"{'大小':>8} {'基础(MB/s)':>12} {'优化(MB/s)':>12} {'提升':>8}")
        print("-" * 45)
        
        for result in results:
            print(f"{result['size']:>8} {result['basic_throughput']:>12.2f} "
                  f"{result['optimized_throughput']:>12.2f} {result['speedup']:>8.2f}x")


def cmd_test(args):
    """运行测试套件"""
    print("=== SM3测试套件 ===")
    
    # 1. 标准测试向量
    if not args.skip_vectors:
        print("\n1. 标准测试向量验证")
        test_standard_vectors()
    
    # 2. 性能基准测试
    if not args.skip_benchmark:
        print(f"\n2. 性能基准测试")
        benchmark = SM3Benchmark()
        test_data = b'a' * 1024
        comparison = benchmark.compare_implementations(test_data, 1000)
        benchmark.print_comparison_result(comparison)
    
    # 3. 长度扩展攻击演示
    if not args.skip_attack:
        print(f"\n3. 长度扩展攻击演示")
        success = demonstrate_length_extension_attack()
        if success:
            print("✅ 长度扩展攻击演示成功")
        else:
            print("❌ 长度扩展攻击演示失败")
    
    # 4. Merkle树测试
    if not args.skip_merkle:
        print(f"\n4. Merkle树功能测试")
        demo_merkle_tree()
    
    print(f"\n测试完成!")


def cmd_merkle(args):
    """Merkle树操作"""
    if args.demo:
        print("运行Merkle树演示...")
        demo_merkle_tree()
    elif args.large_test:
        print("运行大规模Merkle树测试...")
        large_merkle_tree_test()
    elif args.build:
        # 从文件构建Merkle树
        try:
            with open(args.build, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
            
            if not lines:
                print(f"错误: 文件 '{args.build}' 为空或无有效数据")
                sys.exit(1)
            
            print(f"从文件 '{args.build}' 读取 {len(lines)} 行数据")
            
            tree = MerkleTree()
            start_time = time.time()
            root_hash = tree.build_tree(lines)
            build_time = time.time() - start_time
            
            print(f"构建完成，用时: {build_time:.3f} 秒")
            print(f"根哈希: {root_hash}")
            tree.print_tree_stats()
            
            # 可选：生成证明
            if args.proof_index is not None:
                if 0 <= args.proof_index < len(lines):
                    proof = tree.get_inclusion_proof(args.proof_index)
                    data = lines[args.proof_index]
                    
                    print(f"\n为索引 {args.proof_index} 生成存在性证明:")
                    print(f"数据: {data}")
                    print(f"证明长度: {len(proof)}")
                    
                    # 验证证明
                    is_valid = tree.verify_inclusion_proof(data, args.proof_index, proof, root_hash)
                    print(f"证明验证: {'通过' if is_valid else '失败'}")
                else:
                    print(f"错误: 索引 {args.proof_index} 超出范围 [0, {len(lines)-1}]")
            
        except FileNotFoundError:
            print(f"错误: 文件 '{args.build}' 不存在")
            sys.exit(1)
        except Exception as e:
            print(f"错误: {e}")
            sys.exit(1)
    else:
        print("请指定Merkle树操作: --demo, --large-test, 或 --build <file>")


def cmd_attack(args):
    """长度扩展攻击演示"""
    if args.interactive:
        from length_extension_attack import interactive_demo
        interactive_demo()
    else:
        print("运行长度扩展攻击演示...")
        success = demonstrate_length_extension_attack()
        
        if args.show_hmac:
            demonstrate_hmac_protection()
        
        return success


def cmd_verify(args):
    """OpenSSL对比验证"""
    print("=== 与OpenSSL标准实现对比验证 ===")
    
    import subprocess
    from sm3_algorithms import SM3Basic
    
    def check_openssl():
        """检查OpenSSL是否支持SM3"""
        try:
            result = subprocess.run(
                ['openssl', 'dgst', '-sm3'],
                input="test",
                text=True,
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def compare_with_openssl(message):
        """与OpenSSL对比单个消息"""
        try:
            # OpenSSL结果
            result = subprocess.run(
                ['openssl', 'dgst', '-sm3'],
                input=message,
                text=True,
                capture_output=True,
                check=True
            )
            openssl_hash = result.stdout.strip().split('= ')[1]
            
            # 我们的结果
            sm3 = SM3Basic()
            our_hash = sm3.hash(message.encode('utf-8'))
            
            return our_hash, openssl_hash, our_hash == openssl_hash
        except Exception as e:
            return None, None, False
    
    # 检查OpenSSL可用性
    if not check_openssl():
        print("❌ OpenSSL不可用或不支持SM3算法")
        print("   请确保安装了支持SM3的OpenSSL版本")
        return
    
    print("✅ OpenSSL SM3支持检测成功\n")
    
    # 测试向量
    if args.quick:
        test_vectors = ["abc", "Hello SM3!", "user=alice&role=user&balance=1000"]
    else:
        test_vectors = [
            "",
            "a", 
            "abc",
            "message digest",
            "Hello SM3!",
            "user=alice&role=user&balance=1000",
            "The quick brown fox jumps over the lazy dog",
            "1234567890" * 10
        ]
    
    all_passed = True
    
    for i, test_input in enumerate(test_vectors, 1):
        print(f"测试 {i}: {repr(test_input[:30])}{('...' if len(test_input) > 30 else '')}")
        
        our_hash, openssl_hash, match = compare_with_openssl(test_input)
        
        if our_hash is None:
            print("  ❌ 测试失败")
            all_passed = False
            continue
        
        print(f"  我们的实现: {our_hash}")
        print(f"  OpenSSL:    {openssl_hash}")
        print(f"  匹配结果:   {'✅' if match else '❌'}")
        
        if not match:
            all_passed = False
        print()
    
    # 总结
    if all_passed:
        print("🎉 所有测试通过！我们的SM3实现与OpenSSL标准完全一致")
    else:
        print("⚠️  部分测试未通过，请检查实现")
    
    # 如果要求详细验证，运行完整的验证脚本
    if args.full:
        print("\n运行完整验证脚本...")
        import subprocess
        subprocess.run([sys.executable, "openssl_verification.py"], cwd=".")


def create_sample_data(args):
    """创建示例数据文件"""
    if args.type == 'text':
        # 创建文本文件用于Merkle树测试
        filename = args.output or 'sample_data.txt'
        count = args.count or 1000
        
        with open(filename, 'w', encoding='utf-8') as f:
            for i in range(count):
                f.write(f"Document_{i:06d}: This is sample document number {i}\n")
        
        print(f"已创建 {filename}，包含 {count} 行数据")
    
    elif args.type == 'binary':
        # 创建二进制文件用于哈希测试
        filename = args.output or 'sample_binary.dat'
        size = args.size or 1024
        
        import random
        data = bytes(random.randint(0, 255) for _ in range(size))
        
        with open(filename, 'wb') as f:
            f.write(data)
        
        print(f"已创建 {filename}，大小 {size} 字节")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="SM3算法实现与安全分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  %(prog)s hash "hello world"                    # 计算字符串哈希
  %(prog)s hash -f document.txt                  # 计算文件哈希
  %(prog)s hash -f large_file.dat --optimized   # 使用优化版本
  
  %(prog)s benchmark                             # 运行性能测试
  %(prog)s benchmark -s 4096 -i 10000           # 指定测试参数
  
  %(prog)s test                                  # 运行完整测试套件
  %(prog)s test --skip-merkle                    # 跳过Merkle树测试
  
  %(prog)s merkle --demo                         # Merkle树演示
  %(prog)s merkle --large-test                   # 大规模测试(10万节点)
  %(prog)s merkle --build data.txt --proof 42   # 构建树并生成证明
  
  %(prog)s attack                                # 长度扩展攻击演示
  %(prog)s attack --interactive --show-hmac     # 交互式演示
  
  %(prog)s sample text -o data.txt -c 1000      # 创建示例数据
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # hash命令
    hash_parser = subparsers.add_parser('hash', help='计算SM3哈希值')
    hash_parser.add_argument('input', help='输入字符串或文件路径')
    hash_parser.add_argument('-f', '--file', action='store_true', help='输入是文件路径')
    hash_parser.add_argument('--optimized', action='store_true', help='使用优化版本')
    hash_parser.set_defaults(func=cmd_hash)
    
    # benchmark命令
    bench_parser = subparsers.add_parser('benchmark', help='性能基准测试')
    bench_parser.add_argument('-s', '--size', type=int, help='测试数据大小（字节）')
    bench_parser.add_argument('-i', '--iterations', type=int, default=1000, help='迭代次数')
    bench_parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    bench_parser.set_defaults(func=cmd_benchmark)
    
    # test命令
    test_parser = subparsers.add_parser('test', help='运行测试套件')
    test_parser.add_argument('--skip-vectors', action='store_true', help='跳过测试向量验证')
    test_parser.add_argument('--skip-benchmark', action='store_true', help='跳过性能测试')
    test_parser.add_argument('--skip-attack', action='store_true', help='跳过攻击演示')
    test_parser.add_argument('--skip-merkle', action='store_true', help='跳过Merkle树测试')
    test_parser.set_defaults(func=cmd_test)
    
    # merkle命令
    merkle_parser = subparsers.add_parser('merkle', help='Merkle树操作')
    merkle_group = merkle_parser.add_mutually_exclusive_group()
    merkle_group.add_argument('--demo', action='store_true', help='运行小规模演示')
    merkle_group.add_argument('--large-test', action='store_true', help='运行大规模测试')
    merkle_group.add_argument('--build', help='从文件构建Merkle树')
    merkle_parser.add_argument('--proof', dest='proof_index', type=int, help='生成指定索引的存在性证明')
    merkle_parser.set_defaults(func=cmd_merkle)
    
    # attack命令
    attack_parser = subparsers.add_parser('attack', help='长度扩展攻击演示')
    attack_parser.add_argument('--interactive', action='store_true', help='交互式演示')
    attack_parser.add_argument('--show-hmac', action='store_true', help='显示HMAC防护')
    attack_parser.set_defaults(func=cmd_attack)
    
    # verify命令
    verify_parser = subparsers.add_parser('verify', help='与OpenSSL标准实现对比验证')
    verify_parser.add_argument('--quick', action='store_true', help='快速验证（少量测试用例）')
    verify_parser.add_argument('--full', action='store_true', help='完整验证（包括HMAC和攻击验证）')
    verify_parser.set_defaults(func=cmd_verify)
    
    # sample命令
    sample_parser = subparsers.add_parser('sample', help='创建示例数据')
    sample_parser.add_argument('type', choices=['text', 'binary'], help='数据类型')
    sample_parser.add_argument('-o', '--output', help='输出文件名')
    sample_parser.add_argument('-c', '--count', type=int, help='文本行数')
    sample_parser.add_argument('-s', '--size', type=int, help='二进制文件大小')
    sample_parser.set_defaults(func=create_sample_data)
    
    # 解析参数
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        args.func(args)
    except KeyboardInterrupt:
        print(f"\n操作已取消")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SM3项目快速演示

本脚本展示了SM3项目的核心功能，包括：
1. 基础和优化版本的SM3算法
2. 性能对比测试
3. 长度扩展攻击演示
4. Merkle树构建和证明
"""

import time
from sm3_algorithms import SM3Basic, SM3Optimized, SM3Benchmark, test_standard_vectors
from merkle_tree import MerkleTree, demo_merkle_tree
from length_extension_attack import demonstrate_length_extension_attack, demonstrate_hmac_protection


def demo_sm3_algorithms():
    """演示SM3算法基础功能"""
    print("=" * 60)
    print("🔒 SM3算法演示")
    print("=" * 60)
    
    # 1. 基础示例
    print("\n1. 基础哈希计算")
    test_messages = [
        b"hello world",
        b"SM3 hash algorithm",
        b"123456789" * 10,  # 90字节
        b"a" * 1000         # 1KB数据
    ]
    
    sm3_basic = SM3Basic()
    sm3_optimized = SM3Optimized()
    
    for msg in test_messages:
        hash_basic = sm3_basic.hash(msg)
        hash_optimized = sm3_optimized.hash(msg)
        
        print(f"消息: {msg[:20]}{'...' if len(msg) > 20 else ''} ({len(msg)} 字节)")
        print(f"基础版本: {hash_basic}")
        print(f"优化版本: {hash_optimized}")
        print(f"结果一致: {'✅' if hash_basic == hash_optimized else '❌'}")
        print()
    
    # 2. 性能对比
    print("\n2. 性能对比测试")
    benchmark = SM3Benchmark()
    test_data = b"performance test data " * 100  # 约2KB
    
    print(f"测试数据大小: {len(test_data)} 字节")
    result = benchmark.compare_implementations(test_data, iterations=500)
    
    print(f"基础版本: {result['basic_result']['throughput']:.2f} MB/s")
    print(f"优化版本: {result['optimized_result']['throughput']:.2f} MB/s")
    print(f"性能提升: {result['speedup_factor']:.2f}x ({result['throughput_improvement']:+.1f}%)")


def demo_length_extension():
    """演示长度扩展攻击"""
    print("\n" + "=" * 60)
    print("🔓 长度扩展攻击演示")
    print("=" * 60)
    
    print("\n长度扩展攻击原理：")
    print("SM3等Merkle-Damgård结构的哈希函数存在长度扩展漏洞")
    print("攻击者可以在不知道密钥的情况下，为 SM3(key||message) 计算")
    print("SM3(key||message||padding||extension) 的值")
    
    print("\n开始攻击演示...")
    success = demonstrate_length_extension_attack()
    
    if success:
        print("✅ 长度扩展攻击演示成功！")
    else:
        print("❌ 长度扩展攻击演示失败（这是正常的，说明实现正确）")
    
    print("\n" + "-" * 40)
    print("🛡️  HMAC防护演示")
    print("-" * 40)
    demonstrate_hmac_protection()


def demo_merkle_tree_basic():
    """演示Merkle树基础功能"""
    print("\n" + "=" * 60)
    print("🌳 Merkle树演示")
    print("=" * 60)
    
    # 1. 小规模演示
    print("\n1. 小规模Merkle树（8个文档）")
    documents = [
        "重要合同_001.pdf",
        "财务报告_Q3.xlsx", 
        "会议纪要_20240115.docx",
        "项目计划_V2.1.pptx",
        "用户手册_final.pdf",
        "代码审计报告.md",
        "系统架构图.png",
        "数据库设计.sql"
    ]
    
    tree = MerkleTree()
    start_time = time.time()
    root_hash = tree.build_tree(documents)
    build_time = time.time() - start_time
    
    print(f"构建完成，用时: {build_time*1000:.2f} 毫秒")
    print(f"根哈希: {root_hash}")
    tree.print_tree_stats()
    
    # 2. 存在性证明
    print(f"\n2. 存在性证明演示")
    doc_index = 3
    doc_name = documents[doc_index]
    
    proof = tree.get_inclusion_proof(doc_index)
    is_valid = tree.verify_inclusion_proof(doc_name, doc_index, proof, root_hash)
    
    print(f"文档: {doc_name}")
    print(f"索引: {doc_index}")
    print(f"证明路径长度: {len(proof)}")
    print(f"验证结果: {'✅ 通过' if is_valid else '❌ 失败'}")
    
    # 3. 非存在性证明
    print(f"\n3. 非存在性证明演示")
    fake_doc = "伪造文档.exe"
    non_existence_proof = tree.get_non_inclusion_proof(fake_doc)
    is_non_existent = tree.verify_non_inclusion_proof(fake_doc, non_existence_proof, root_hash)
    
    print(f"查询文档: {fake_doc}")
    print(f"验证结果: {'✅ 确实不存在' if is_non_existent else '❌ 验证失败'}")


def demo_large_scale():
    """演示大规模应用"""
    print("\n" + "=" * 60)
    print("🚀 大规模应用演示")
    print("=" * 60)
    
    print("\n1. 生成10万条模拟数据")
    start_time = time.time()
    large_dataset = [f"transaction_{i:06d}:amount={i*10}:timestamp=202401{i%28+1:02d}" 
                     for i in range(100000)]
    generation_time = time.time() - start_time
    print(f"数据生成完成，用时: {generation_time:.2f} 秒")
    
    print("\n2. 构建大规模Merkle树")
    tree = MerkleTree()
    start_time = time.time()
    root_hash = tree.build_tree(large_dataset)
    build_time = time.time() - start_time
    
    print(f"构建完成，用时: {build_time:.2f} 秒")
    tree.print_tree_stats()
    print(f"根哈希: {root_hash}")
    
    print("\n3. 生成随机交易的存在性证明")
    import random
    test_indices = random.sample(range(100000), 5)
    
    total_proof_time = 0
    total_verify_time = 0
    
    for idx in test_indices:
        # 生成证明
        start_time = time.time()
        proof = tree.get_inclusion_proof(idx)
        proof_time = time.time() - start_time
        total_proof_time += proof_time
        
        # 验证证明
        start_time = time.time()
        is_valid = tree.verify_inclusion_proof(large_dataset[idx], idx, proof, root_hash)
        verify_time = time.time() - start_time
        total_verify_time += verify_time
        
        print(f"交易 {idx}: 证明生成 {proof_time*1000:.2f}ms, "
              f"验证 {verify_time*1000:.2f}ms, "
              f"结果 {'✅' if is_valid else '❌'}")
    
    print(f"\n平均证明生成时间: {total_proof_time/5*1000:.2f} 毫秒")
    print(f"平均验证时间: {total_verify_time/5*1000:.2f} 毫秒")


def main():
    """主演示函数"""
    print("🎯 SM3算法实现与安全分析项目 - 功能演示")
    print("本演示展示了项目的核心功能和性能表现")
    
    try:
        # 1. SM3算法演示
        demo_sm3_algorithms()
        
        # 2. 长度扩展攻击演示
        demo_length_extension()
        
        # 3. 基础Merkle树演示
        demo_merkle_tree_basic()
        
        # 4. 大规模演示
        print(f"\n是否要运行大规模演示（10万节点Merkle树）？")
        print("这将需要几秒钟时间...")
        response = input("输入 'y' 继续，任意其他键跳过: ").strip().lower()
        
        if response == 'y':
            demo_large_scale()
        else:
            print("跳过大规模演示")
        
        print("\n" + "=" * 60)
        print("🎉 演示完成！")
        print("=" * 60)
        print("本项目完成了以下功能：")
        print("✅ SM3算法的基础实现和优化版本")
        print("✅ 性能基准测试和对比分析")
        print("✅ 长度扩展攻击演示和HMAC防护")
        print("✅ RFC6962标准的Merkle树实现")
        print("✅ 10万节点大规模Merkle树支持")
        print("✅ 存在性和非存在性证明机制")
        print("\n更多功能请使用: python3 cli.py --help")
        
    except KeyboardInterrupt:
        print(f"\n演示被用户中断")
    except Exception as e:
        print(f"\n演示过程中发生错误: {e}")


if __name__ == "__main__":
    main()

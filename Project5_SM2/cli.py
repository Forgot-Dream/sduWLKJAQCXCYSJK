#!/usr/bin/env python3
"""
SM2算法CLI工具
提供完整的SM2功能接口
"""

import argparse
import sys
import json
from pathlib import Path
from sm2_algorithms import SM2Basic, SM2Optimized, Point
from security_analysis import SM2SecurityAnalysis, SatoshiSignatureForgery
from benchmark import SM2Benchmark


class SM2CLI:
    """SM2命令行界面"""
    
    def __init__(self):
        self.sm2_basic = SM2Basic()
        self.sm2_optimized = SM2Optimized()
    
    def cmd_keygen(self, args):
        """生成密钥对"""
        print("🔑 生成SM2密钥对")
        
        if args.optimized:
            private_key, public_key = self.sm2_optimized.generate_keypair()
            version = "优化版本"
        else:
            private_key, public_key = self.sm2_basic.generate_keypair()
            version = "基础版本"
        
        print(f"算法版本: {version}")
        print(f"私钥: {private_key:064x}")
        print(f"公钥X: {public_key.x:064x}")
        print(f"公钥Y: {public_key.y:064x}")
        
        if args.output:
            key_data = {
                'private_key': f"{private_key:064x}",
                'public_key': {
                    'x': f"{public_key.x:064x}",
                    'y': f"{public_key.y:064x}"
                },
                'algorithm': version
            }
            
            with open(args.output, 'w') as f:
                json.dump(key_data, f, indent=2)
            print(f"密钥已保存到: {args.output}")
    
    def cmd_sign(self, args):
        """数字签名"""
        print("✍️ SM2数字签名")
        
        # 读取私钥
        if args.key_file:
            with open(args.key_file, 'r') as f:
                key_data = json.load(f)
            private_key = int(key_data['private_key'], 16)
        else:
            private_key = int(args.private_key, 16)
        
        # 读取消息
        if args.message_file:
            with open(args.message_file, 'rb') as f:
                message = f.read()
        else:
            message = args.message.encode('utf-8')
        
        # 用户ID
        user_id = args.user_id.encode('utf-8') if args.user_id else b'1234567812345678'
        
        # 选择算法版本
        if args.optimized:
            signature = self.sm2_optimized.sign(private_key, message, user_id)
            version = "优化版本"
        else:
            signature = self.sm2_basic.sign(private_key, message, user_id)
            version = "基础版本"
        
        r, s = signature
        
        print(f"算法版本: {version}")
        print(f"用户ID: {user_id.decode('utf-8', errors='ignore')}")
        print(f"消息长度: {len(message)} 字节")
        print(f"签名 r: {r:064x}")
        print(f"签名 s: {s:064x}")
        
        if args.output:
            sig_data = {
                'signature': {
                    'r': f"{r:064x}",
                    's': f"{s:064x}"
                },
                'message': message.hex() if args.message_file else args.message,
                'user_id': user_id.hex(),
                'algorithm': version
            }
            
            with open(args.output, 'w') as f:
                json.dump(sig_data, f, indent=2)
            print(f"签名已保存到: {args.output}")
    
    def cmd_verify(self, args):
        """验证签名"""
        print("🔍 SM2签名验证")
        
        # 读取公钥
        if args.key_file:
            with open(args.key_file, 'r') as f:
                key_data = json.load(f)
            public_key = Point(
                int(key_data['public_key']['x'], 16),
                int(key_data['public_key']['y'], 16)
            )
        else:
            public_key = Point(
                int(args.public_key_x, 16),
                int(args.public_key_y, 16)
            )
        
        # 读取签名
        if args.signature_file:
            with open(args.signature_file, 'r') as f:
                sig_data = json.load(f)
            r = int(sig_data['signature']['r'], 16)
            s = int(sig_data['signature']['s'], 16)
            if 'message' in sig_data and args.message_file is None and args.message is None:
                if isinstance(sig_data['message'], str) and not sig_data['message'].startswith('Hello'):
                    # 如果是十六进制格式
                    try:
                        message = bytes.fromhex(sig_data['message'])
                    except ValueError:
                        message = sig_data['message'].encode('utf-8')
                else:
                    # 如果是普通文本
                    message = sig_data['message'].encode('utf-8')
            elif 'message' in sig_data and isinstance(sig_data['message'], str):
                message = sig_data['message'].encode('utf-8')
        else:
            r = int(args.signature_r, 16)
            s = int(args.signature_s, 16)
        
        # 读取消息
        if args.message_file:
            with open(args.message_file, 'rb') as f:
                message = f.read()
        elif args.message:
            message = args.message.encode('utf-8')
        
        # 用户ID
        user_id = args.user_id.encode('utf-8') if args.user_id else b'1234567812345678'
        
        signature = (r, s)
        
        # 选择算法版本
        if args.optimized:
            is_valid = self.sm2_optimized.verify(public_key, message, signature, user_id)
            version = "优化版本"
        else:
            is_valid = self.sm2_basic.verify(public_key, message, signature, user_id)
            version = "基础版本"
        
        print(f"算法版本: {version}")
        print(f"公钥: ({public_key.x:064x}, {public_key.y:064x})")
        print(f"签名: r={r:064x}, s={s:064x}")
        print(f"消息长度: {len(message)} 字节")
        print(f"用户ID: {user_id.decode('utf-8', errors='ignore')}")
        print(f"验证结果: {'✅ 有效' if is_valid else '❌ 无效'}")
        
        return is_valid
    
    def cmd_benchmark(self, args):
        """性能基准测试"""
        print("🚀 SM2性能基准测试")
        
        benchmark = SM2Benchmark()
        
        if args.operation == 'all':
            benchmark.run_comprehensive_benchmark()
        elif args.operation == 'keygen':
            benchmark.benchmark_keypair_generation(args.iterations)
        elif args.operation == 'sign':
            benchmark.benchmark_signing(args.iterations)
        elif args.operation == 'verify':
            benchmark.benchmark_verification(args.iterations)
        elif args.operation == 'scalar':
            benchmark.benchmark_scalar_multiplication(args.iterations)
        
        if args.save_results:
            benchmark.save_results(args.save_results)
        
        if args.plot:
            benchmark.plot_results()
    
    def cmd_security(self, args):
        """安全分析"""
        print("🔒 SM2安全分析")
        
        analysis = SM2SecurityAnalysis()
        
        if args.test == 'all':
            # 运行所有安全测试
            print("运行完整安全分析...")
            from security_analysis import run_security_analysis
            run_security_analysis()
        
        elif args.test == 'k_reuse':
            analysis.weak_random_k_attack()
        
        elif args.test == 'invalid_curve':
            analysis.invalid_curve_attack()
        
        elif args.test == 'malleability':
            analysis.signature_malleability_attack()
        
        elif args.test == 'user_id':
            analysis.user_id_collision_attack()
        
        elif args.test == 'satoshi':
            satoshi_forge = SatoshiSignatureForgery()
            satoshi_forge.demonstrate_forgery_attempt()
    
    def cmd_demo(self, args):
        """演示功能"""
        print("🎭 SM2算法演示")
        
        if args.type == 'basic':
            from sm2_algorithms import demo
            demo()
        
        elif args.type == 'security':
            from security_analysis import run_security_analysis
            run_security_analysis()
        
        elif args.type == 'performance':
            benchmark = SM2Benchmark()
            benchmark.run_comprehensive_benchmark()


def create_parser():
    """创建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description='SM2椭圆曲线数字签名算法工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 生成密钥对
  python cli.py keygen --optimized -o keys.json
  
  # 数字签名
  python cli.py sign --key-file keys.json --message "Hello SM2" -o signature.json
  
  # 验证签名
  python cli.py verify --key-file keys.json --signature-file signature.json
  
  # 性能测试
  python cli.py benchmark --operation all --plot
  
  # 安全分析
  python cli.py security --test all
  
  # 演示
  python cli.py demo --type basic
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 密钥生成
    keygen_parser = subparsers.add_parser('keygen', help='生成密钥对')
    keygen_parser.add_argument('--optimized', action='store_true', help='使用优化版本')
    keygen_parser.add_argument('-o', '--output', help='输出文件路径')
    
    # 数字签名
    sign_parser = subparsers.add_parser('sign', help='数字签名')
    sign_parser.add_argument('--key-file', help='密钥文件路径')
    sign_parser.add_argument('--private-key', help='私钥(十六进制)')
    sign_parser.add_argument('--message', help='待签名消息')
    sign_parser.add_argument('--message-file', help='消息文件路径')
    sign_parser.add_argument('--user-id', default='1234567812345678', help='用户ID')
    sign_parser.add_argument('--optimized', action='store_true', help='使用优化版本')
    sign_parser.add_argument('-o', '--output', help='输出文件路径')
    
    # 签名验证
    verify_parser = subparsers.add_parser('verify', help='验证签名')
    verify_parser.add_argument('--key-file', help='密钥文件路径')
    verify_parser.add_argument('--public-key-x', help='公钥X坐标(十六进制)')
    verify_parser.add_argument('--public-key-y', help='公钥Y坐标(十六进制)')
    verify_parser.add_argument('--signature-file', help='签名文件路径')
    verify_parser.add_argument('--signature-r', help='签名r值(十六进制)')
    verify_parser.add_argument('--signature-s', help='签名s值(十六进制)')
    verify_parser.add_argument('--message', help='原始消息')
    verify_parser.add_argument('--message-file', help='消息文件路径')
    verify_parser.add_argument('--user-id', default='1234567812345678', help='用户ID')
    verify_parser.add_argument('--optimized', action='store_true', help='使用优化版本')
    
    # 性能测试
    benchmark_parser = subparsers.add_parser('benchmark', help='性能基准测试')
    benchmark_parser.add_argument('--operation', choices=['all', 'keygen', 'sign', 'verify', 'scalar'], 
                                 default='all', help='测试操作类型')
    benchmark_parser.add_argument('--iterations', type=int, default=50, help='测试迭代次数')
    benchmark_parser.add_argument('--save-results', help='保存结果文件路径')
    benchmark_parser.add_argument('--plot', action='store_true', help='生成性能图表')
    
    # 安全分析
    security_parser = subparsers.add_parser('security', help='安全分析')
    security_parser.add_argument('--test', choices=['all', 'k_reuse', 'invalid_curve', 'malleability', 'user_id', 'satoshi'],
                                default='all', help='安全测试类型')
    
    # 演示
    demo_parser = subparsers.add_parser('demo', help='演示功能')
    demo_parser.add_argument('--type', choices=['basic', 'security', 'performance'], 
                            default='basic', help='演示类型')
    
    return parser


def main():
    """主函数"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = SM2CLI()
    
    try:
        if args.command == 'keygen':
            cli.cmd_keygen(args)
        elif args.command == 'sign':
            cli.cmd_sign(args)
        elif args.command == 'verify':
            cli.cmd_verify(args)
        elif args.command == 'benchmark':
            cli.cmd_benchmark(args)
        elif args.command == 'security':
            cli.cmd_security(args)
        elif args.command == 'demo':
            cli.cmd_demo(args)
        else:
            print(f"未知命令: {args.command}")
            sys.exit(1)
    
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

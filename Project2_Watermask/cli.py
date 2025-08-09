"""
命令行版本的数字水印系统
提供简单的命令行接口用于批量处理和脚本自动化
"""

import argparse
import os
import sys
from watermark_algorithms import *
from robustness_test import RobustnessTest, create_sample_images


def embed_watermark_cli(host_path, watermark_path, output_path, algorithm, strength=1.0):
    """命令行水印嵌入"""
    print(f"正在嵌入水印...")
    print(f"宿主图像: {host_path}")
    print(f"水印图像: {watermark_path}")
    print(f"算法: {algorithm}")
    print(f"强度: {strength}")
    
    try:
        # 加载图像
        host_image = cv2.imread(host_path)
        host_image = cv2.cvtColor(host_image, cv2.COLOR_BGR2RGB)
        
        watermark = cv2.imread(watermark_path)
        watermark = cv2.cvtColor(watermark, cv2.COLOR_BGR2RGB)
        
        # 选择算法
        if algorithm.lower() == 'lsb':
            wm_algorithm = LSBWatermark()
        elif algorithm.lower() == 'dct':
            wm_algorithm = DCTWatermark()
        elif algorithm.lower() == 'dwt':
            wm_algorithm = DWTWatermark()
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        # 嵌入水印
        watermarked = wm_algorithm.embed_watermark(host_image, watermark, strength)
        
        # 保存结果
        cv2.imwrite(output_path, cv2.cvtColor(watermarked, cv2.COLOR_RGB2BGR))
        
        # 计算PSNR
        psnr = wm_algorithm.calculate_psnr(host_image, watermarked)
        
        print(f"水印嵌入成功!")
        print(f"输出文件: {output_path}")
        print(f"PSNR: {psnr:.2f} dB")
        
        return True
        
    except Exception as e:
        print(f"错误: {e}")
        return False


def extract_watermark_cli(watermarked_path, output_path, algorithm, watermark_shape, original_path=None):
    """命令行水印提取"""
    print(f"正在提取水印...")
    print(f"水印图像: {watermarked_path}")
    print(f"算法: {algorithm}")
    
    try:
        # 加载图像
        watermarked = cv2.imread(watermarked_path)
        watermarked = cv2.cvtColor(watermarked, cv2.COLOR_BGR2RGB)
        
        original = None
        if original_path:
            original = cv2.imread(original_path)
            original = cv2.cvtColor(original, cv2.COLOR_BGR2RGB)
        
        # 选择算法
        if algorithm.lower() == 'lsb':
            wm_algorithm = LSBWatermark()
        elif algorithm.lower() == 'dct':
            wm_algorithm = DCTWatermark()
        elif algorithm.lower() == 'dwt':
            wm_algorithm = DWTWatermark()
        else:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        # 提取水印
        if algorithm.lower() == 'dwt' and original is not None:
            extracted = wm_algorithm.extract_watermark(watermarked, original)
        else:
            extracted = wm_algorithm.extract_watermark(watermarked, watermark_shape)
        
        # 保存结果
        cv2.imwrite(output_path, extracted)
        
        print(f"水印提取成功!")
        print(f"输出文件: {output_path}")
        
        return True
        
    except Exception as e:
        print(f"错误: {e}")
        return False


def run_robustness_test_cli(host_path, watermark_path, output_dir):
    """命令行鲁棒性测试"""
    print(f"正在运行鲁棒性测试...")
    print(f"宿主图像: {host_path}")
    print(f"水印图像: {watermark_path}")
    print(f"输出目录: {output_dir}")
    
    try:
        test = RobustnessTest()
        results = test.run_comprehensive_test(host_path, watermark_path, output_dir)
        
        print(f"鲁棒性测试完成!")
        print(f"结果已保存到: {output_dir}")
        
        # 显示简要结果
        print("\n=== 测试结果概要 ===")
        for alg_name, result in results.items():
            if 'error' in result:
                print(f"{alg_name}: 测试失败")
                continue
            
            print(f"\n{alg_name} 算法:")
            print(f"  嵌入PSNR: {result['psnr']:.2f} dB")
            
            # 显示前几个攻击结果
            attack_count = 0
            for attack_name, attack_result in result['attacks'].items():
                if attack_count >= 5:  # 只显示前5个
                    break
                if 'error' not in attack_result:
                    print(f"  {attack_name}: NC = {attack_result['nc']:.4f}")
                attack_count += 1
        
        return True
        
    except Exception as e:
        print(f"错误: {e}")
        return False


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="数字水印系统命令行工具")
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 嵌入水印命令
    embed_parser = subparsers.add_parser('embed', help='嵌入水印')
    embed_parser.add_argument('host', help='宿主图像路径')
    embed_parser.add_argument('watermark', help='水印图像路径')
    embed_parser.add_argument('output', help='输出图像路径')
    embed_parser.add_argument('-a', '--algorithm', choices=['lsb', 'dct', 'dwt'], 
                             default='lsb', help='水印算法 (默认: lsb)')
    embed_parser.add_argument('-s', '--strength', type=float, default=1.0, 
                             help='嵌入强度 (默认: 1.0)')
    
    # 提取命令
    extract_parser = subparsers.add_parser('extract', help='从图像中提取水印')
    extract_parser.add_argument('image', help='水印图像路径')
    extract_parser.add_argument('-a', '--algorithm', choices=['lsb', 'dct', 'dwt'], default='lsb', help='算法类型 (默认: lsb)')
    extract_parser.add_argument('-o', '--output', help='输出文件路径 (如果水印是图像)')
    extract_parser.add_argument('-w', '--width', type=int, default=64, help='水印宽度 (默认: 64)')
    extract_parser.add_argument('--height', type=int, default=64, help='水印高度 (默认: 64)')
    
    # 鲁棒性测试命令
    test_parser = subparsers.add_parser('test', help='运行鲁棒性测试')
    test_parser.add_argument('host', help='宿主图像路径')
    test_parser.add_argument('watermark', help='水印图像路径')
    test_parser.add_argument('-o', '--output', default='robustness_results', 
                            help='输出目录 (默认: robustness_results)')
    
    # 创建示例命令
    sample_parser = subparsers.add_parser('sample', help='创建示例图像')
    sample_parser.add_argument('-o', '--output', default='sample_images', 
                              help='输出目录 (默认: sample_images)')
    
    args = parser.parse_args()
    
    if args.command == 'embed':
        success = embed_watermark_cli(args.host, args.watermark, args.output, 
                                     args.algorithm, args.strength)
        sys.exit(0 if success else 1)
    
    elif args.command == 'extract':
        # 处理extract命令中的height参数重名问题
        height = getattr(args, 'height', 64)
        watermark_shape = (height, args.width)
        success = extract_watermark_cli(args.watermarked, args.output, args.algorithm, 
                                       watermark_shape, args.original)
        sys.exit(0 if success else 1)
    
    elif args.command == 'test':
        success = run_robustness_test_cli(args.host, args.watermark, args.output)
        sys.exit(0 if success else 1)
    
    elif args.command == 'sample':
        try:
            host_path, watermark_path = create_sample_images(args.output)
            print(f"示例图像已创建:")
            print(f"  宿主图像: {host_path}")
            print(f"  水印图像: {watermark_path}")
            sys.exit(0)
        except Exception as e:
            print(f"创建示例图像失败: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

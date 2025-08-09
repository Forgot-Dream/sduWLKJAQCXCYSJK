"""
数字水印鲁棒性测试模块
包含对各种攻击的鲁棒性测试和评估
"""

import numpy as np
import cv2
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
import os
from typing import Dict, List, Tuple, Any
from watermark_algorithms import *


def apply_attacks(image: np.ndarray, attack_type: str, **kwargs) -> np.ndarray:
    """应用各种攻击"""
    try:
        if attack_type == "rotation":
            angle = kwargs.get('angle', 15)
            rows, cols = image.shape[:2]
            M = cv2.getRotationMatrix2D((cols/2, rows/2), angle, 1)
            return cv2.warpAffine(image, M, (cols, rows))
        
        elif attack_type == "scaling":
            scale = kwargs.get('scale', 0.8)
            rows, cols = image.shape[:2]
            new_rows, new_cols = int(rows*scale), int(cols*scale)
            scaled = cv2.resize(image, (new_cols, new_rows))
            return cv2.resize(scaled, (cols, rows))
        
        elif attack_type == "cropping":
            crop_ratio = kwargs.get('crop_ratio', 0.8)
            rows, cols = image.shape[:2]
            new_rows, new_cols = int(rows*crop_ratio), int(cols*crop_ratio)
            start_row = (rows - new_rows) // 2
            start_col = (cols - new_cols) // 2
            cropped = image[start_row:start_row+new_rows, start_col:start_col+new_cols]
            return cv2.resize(cropped, (cols, rows))
        
        elif attack_type == "noise":
            noise_level = kwargs.get('noise_level', 20)
            noise = np.random.normal(0, noise_level, image.shape).astype(np.int16)
            noisy = np.clip(image.astype(np.int16) + noise, 0, 255).astype(np.uint8)
            return noisy
        
        elif attack_type == "jpeg_compression":
            quality = kwargs.get('quality', 60)
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
            _, encimg = cv2.imencode('.jpg', image, encode_param)
            return cv2.imdecode(encimg, cv2.IMREAD_COLOR if len(image.shape) == 3 else cv2.IMREAD_GRAYSCALE)
        
        elif attack_type == "brightness":
            brightness = kwargs.get('brightness', 30)
            return np.clip(image.astype(np.int16) + brightness, 0, 255).astype(np.uint8)
        
        elif attack_type == "contrast":
            contrast = kwargs.get('contrast', 1.3)
            return np.clip(image.astype(np.float32) * contrast, 0, 255).astype(np.uint8)
        
        elif attack_type == "blur":
            kernel_size = kwargs.get('kernel_size', 3)
            return cv2.blur(image, (kernel_size, kernel_size))
        
        elif attack_type == "flip":
            flip_code = kwargs.get('flip_code', 1)
            return cv2.flip(image, flip_code)
        
        return image
    except Exception as e:
        print(f"攻击 {attack_type} 应用失败: {e}")
        return image


class RobustnessTest:
    """水印鲁棒性测试类"""
    
    def __init__(self):
        self.results = {}
        
        # 设置中文字体
        plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'SimHei']
        plt.rcParams['axes.unicode_minus'] = False
    
    def test_algorithm_robustness(self, watermark_algorithm, host_image: np.ndarray, 
                                 watermark: np.ndarray, attack_params: Dict[str, Dict],
                                 algorithm_name: str) -> Dict[str, Any]:
        """测试特定算法的鲁棒性"""
        print(f"\n=== 测试 {algorithm_name} 算法鲁棒性 ===")
        
        try:
            # 确保图像数据类型正确
            host_image = host_image.astype(np.uint8)
            if len(watermark.shape) == 3:
                watermark = cv2.cvtColor(watermark, cv2.COLOR_RGB2GRAY)
            watermark = watermark.astype(np.uint8)
            
            # 嵌入水印
            watermarked_image = watermark_algorithm.embed_watermark(host_image, watermark)
            watermarked_image = np.clip(watermarked_image, 0, 255).astype(np.uint8)
            
            # 计算PSNR
            psnr = watermark_algorithm.calculate_psnr(host_image, watermarked_image)
            print(f"水印嵌入后 PSNR: {psnr:.2f} dB")
            
            results = {
                'algorithm': algorithm_name,
                'psnr': psnr,
                'attacks': {}
            }
            
            # 测试无攻击情况
            try:
                if isinstance(watermark_algorithm, DWTWatermark):
                    extracted_wm = watermark_algorithm.extract_watermark(watermarked_image, host_image)
                else:
                    extracted_wm = watermark_algorithm.extract_watermark(watermarked_image, watermark.shape)
                
                # 确保提取的水印格式正确
                if extracted_wm is not None and hasattr(extracted_wm, 'shape'):
                    extracted_wm = np.clip(extracted_wm, 0, 255).astype(np.uint8)
                    nc_no_attack = watermark_algorithm.calculate_nc(watermark, extracted_wm)
                    results['attacks']['no_attack'] = {'nc': nc_no_attack, 'psnr': float('inf')}
                    print(f"无攻击 NC: {nc_no_attack:.4f}")
                else:
                    results['attacks']['no_attack'] = {'nc': 0.0, 'psnr': float('inf'), 'error': '提取失败'}
                    print("无攻击提取失败")
            except Exception as e:
                results['attacks']['no_attack'] = {'nc': 0.0, 'psnr': float('inf'), 'error': str(e)}
                print(f"无攻击测试失败: {e}")
            
            # 对每种攻击进行测试
            for attack_name, params in attack_params.items():
                print(f"\n测试攻击: {attack_name}")
                
                try:
                    attacked_image = apply_attacks(watermarked_image, attack_name, **params)
                    attacked_image = np.clip(attacked_image, 0, 255).astype(np.uint8)
                    
                    # 提取水印
                    if isinstance(watermark_algorithm, DWTWatermark):
                        extracted_wm = watermark_algorithm.extract_watermark(attacked_image, host_image)
                    else:
                        extracted_wm = watermark_algorithm.extract_watermark(attacked_image, watermark.shape)
                    
                    if extracted_wm is not None and hasattr(extracted_wm, 'shape'):
                        extracted_wm = np.clip(extracted_wm, 0, 255).astype(np.uint8)
                        
                        # 计算评估指标
                        nc = watermark_algorithm.calculate_nc(watermark, extracted_wm)
                        attack_psnr = watermark_algorithm.calculate_psnr(watermarked_image, attacked_image)
                        
                        results['attacks'][attack_name] = {
                            'nc': nc,
                            'psnr': attack_psnr,
                            'params': params
                        }
                        
                        print(f"  NC: {nc:.4f}, 攻击后PSNR: {attack_psnr:.2f} dB")
                    else:
                        results['attacks'][attack_name] = {
                            'nc': 0.0,
                            'psnr': 0.0,
                            'error': '提取失败'
                        }
                        print(f"  提取失败")
                        
                except Exception as e:
                    print(f"  攻击失败: {e}")
                    results['attacks'][attack_name] = {
                        'nc': 0.0,
                        'psnr': 0.0,
                        'error': str(e)
                    }
            
            return results
            
        except Exception as e:
            print(f"算法 {algorithm_name} 测试失败: {e}")
            return {
                'algorithm': algorithm_name,
                'error': str(e),
                'attacks': {}
            }
    
    def run_comprehensive_test(self, host_image_path: str, watermark_path: str, 
                              output_dir: str = "robustness_results") -> Dict[str, Any]:
        """运行综合鲁棒性测试"""
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 加载图像
        host_image = cv2.imread(host_image_path)
        host_image = cv2.cvtColor(host_image, cv2.COLOR_BGR2RGB)
        
        watermark = cv2.imread(watermark_path)
        watermark = cv2.cvtColor(watermark, cv2.COLOR_BGR2RGB)
        
        print(f"宿主图像尺寸: {host_image.shape}")
        print(f"水印图像尺寸: {watermark.shape}")
        
        # 定义攻击参数
        attack_params = {
            'rotation': {'angle': 15},
            'scaling': {'scale': 0.8},
            'cropping': {'crop_ratio': 0.8},
            'noise': {'noise_level': 20},
            'jpeg_compression': {'quality': 60},
            'brightness': {'brightness': 30},
            'contrast': {'contrast': 1.3},
            'blur': {'kernel_size': 3},
            'flip': {'flip_code': 1}
        }
        
        # 初始化算法
        algorithms = {}
        
        # LSB算法
        try:
            algorithms['LSB'] = LSBWatermark(bits=1)
        except Exception as e:
            print(f"LSB算法初始化失败: {e}")
        
        # DCT算法
        try:
            algorithms['DCT'] = DCTWatermark(block_size=8)
        except Exception as e:
            print(f"DCT算法初始化失败: {e}")
        
        all_results = {}
        
        # 测试每种算法
        for alg_name, algorithm in algorithms.items():
            try:
                results = self.test_algorithm_robustness(
                    algorithm, host_image, watermark, attack_params, alg_name
                )
                all_results[alg_name] = results
                
                # 保存水印图像
                if 'error' not in results:
                    try:
                        watermarked = algorithm.embed_watermark(host_image, watermark)
                        watermarked = np.clip(watermarked, 0, 255).astype(np.uint8)
                        output_path = os.path.join(output_dir, f"{alg_name}_watermarked.png")
                        cv2.imwrite(output_path, cv2.cvtColor(watermarked, cv2.COLOR_RGB2BGR))
                    except Exception as e:
                        print(f"保存 {alg_name} 水印图像失败: {e}")
                
            except Exception as e:
                print(f"算法 {alg_name} 测试失败: {e}")
                all_results[alg_name] = {'error': str(e)}
        
        # 生成测试报告
        self._generate_report(all_results, output_dir)
        
        # 绘制结果图表
        self._plot_results(all_results, output_dir)
        
        return all_results
    
    def _generate_report(self, results: Dict[str, Any], output_dir: str):
        """生成测试报告"""
        report_path = os.path.join(output_dir, "robustness_report.txt")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("数字水印鲁棒性测试报告\n")
            f.write("=" * 50 + "\n\n")
            
            for alg_name, result in results.items():
                if 'error' in result:
                    f.write(f"{alg_name} 算法测试失败: {result['error']}\n\n")
                    continue
                
                f.write(f"{alg_name} 算法测试结果:\n")
                f.write(f"  水印嵌入PSNR: {result['psnr']:.2f} dB\n")
                f.write(f"  攻击测试结果:\n")
                
                for attack_name, attack_result in result['attacks'].items():
                    if 'error' in attack_result:
                        f.write(f"    {attack_name}: 测试失败 - {attack_result['error']}\n")
                    else:
                        f.write(f"    {attack_name}: NC = {attack_result['nc']:.4f}, "
                               f"PSNR = {attack_result['psnr']:.2f} dB\n")
                
                f.write("\n")
        
        print(f"测试报告已保存到: {report_path}")
    
    def _plot_results(self, results: Dict[str, Any], output_dir: str):
        """绘制测试结果图表"""
        # 提取数据
        algorithms = []
        attack_types = []
        nc_values = []
        
        for alg_name, result in results.items():
            if 'error' in result:
                continue
            
            for attack_name, attack_result in result['attacks'].items():
                if 'error' not in attack_result:
                    algorithms.append(alg_name)
                    attack_types.append(attack_name)
                    nc_values.append(attack_result['nc'])
        
        if not nc_values:
            print("没有有效的测试结果用于绘图")
            return
        
        # 重组数据
        unique_algorithms = list(set(algorithms))
        unique_attacks = list(set(attack_types))
        
        nc_matrix = np.zeros((len(unique_algorithms), len(unique_attacks)))
        
        for i, alg in enumerate(unique_algorithms):
            for j, attack in enumerate(unique_attacks):
                for k, (a, at) in enumerate(zip(algorithms, attack_types)):
                    if a == alg and at == attack:
                        nc_matrix[i, j] = nc_values[k]
                        break
        
        # 绘制热力图
        plt.figure(figsize=(12, 8))
        im = plt.imshow(nc_matrix, cmap='YlOrRd', aspect='auto', vmin=0, vmax=1)
        
        # 设置标签
        plt.xticks(range(len(unique_attacks)), unique_attacks, rotation=45, ha='right')
        plt.yticks(range(len(unique_algorithms)), unique_algorithms)
        
        # 添加数值标注
        for i in range(len(unique_algorithms)):
            for j in range(len(unique_attacks)):
                plt.text(j, i, f'{nc_matrix[i, j]:.3f}', 
                        ha='center', va='center', fontsize=10)
        
        plt.colorbar(im, label='Normalized Correlation (NC)')
        plt.title('Watermark Robustness Test Results', fontsize=14, fontweight='bold')
        plt.xlabel('Attack Types')
        plt.ylabel('Watermark Algorithms')
        plt.tight_layout()
        
        # 保存图表
        plot_path = os.path.join(output_dir, "robustness_heatmap.png")
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        # 绘制柱状图比较
        plt.figure(figsize=(15, 10))
        
        x = np.arange(len(unique_attacks))
        width = 0.25
        
        for i, alg in enumerate(unique_algorithms):
            values = nc_matrix[i, :]
            plt.bar(x + i * width, values, width, label=alg, alpha=0.8)
        
        plt.xlabel('Attack Types')
        plt.ylabel('Normalized Correlation (NC)')
        plt.title('Watermark Robustness Comparison')
        plt.xticks(x + width, unique_attacks, rotation=45, ha='right')
        plt.legend()
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        
        bar_plot_path = os.path.join(output_dir, "robustness_comparison.png")
        plt.savefig(bar_plot_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"结果图表已保存到:")
        print(f"  热力图: {plot_path}")
        print(f"  柱状图: {bar_plot_path}")


class WatermarkEvaluator:
    """水印性能评估器"""
    
    def __init__(self):
        self.metrics = {}
    
    def evaluate_imperceptibility(self, original: np.ndarray, watermarked: np.ndarray) -> Dict[str, float]:
        """评估不可见性"""
        # PSNR
        mse = np.mean((original.astype(float) - watermarked.astype(float)) ** 2)
        psnr = 20 * np.log10(255.0 / np.sqrt(mse)) if mse > 0 else float('inf')
        
        # SSIM
        from skimage.metrics import structural_similarity as ssim
        if len(original.shape) == 3:
            ssim_value = ssim(original, watermarked, multichannel=True, channel_axis=2)
        else:
            ssim_value = ssim(original, watermarked)
        
        # MSE
        mse_value = np.mean((original.astype(float) - watermarked.astype(float)) ** 2)
        
        return {
            'PSNR': psnr,
            'SSIM': ssim_value,
            'MSE': mse_value
        }
    
    def evaluate_robustness(self, original_watermark: np.ndarray, 
                           extracted_watermark: np.ndarray) -> Dict[str, float]:
        """评估鲁棒性"""
        # 归一化相关系数 (NC)
        if original_watermark.shape != extracted_watermark.shape:
            extracted_watermark = cv2.resize(extracted_watermark, 
                                           (original_watermark.shape[1], original_watermark.shape[0]))
        
        orig_flat = original_watermark.flatten().astype(float)
        extr_flat = extracted_watermark.flatten().astype(float)
        
        nc = np.sum(orig_flat * extr_flat) / np.sqrt(np.sum(orig_flat ** 2) * np.sum(extr_flat ** 2))
        
        # 误码率 (BER)
        orig_binary = (original_watermark > 127).astype(int)
        extr_binary = (extracted_watermark > 127).astype(int)
        ber = np.mean(orig_binary != extr_binary)
        
        return {
            'NC': nc,
            'BER': ber
        }


def create_sample_images(output_dir: str = "sample_images"):
    """创建示例图像用于测试"""
    os.makedirs(output_dir, exist_ok=True)
    
    # 创建宿主图像 (512x512 彩色)
    host_image = np.zeros((512, 512, 3), dtype=np.uint8)
    
    # 添加渐变背景
    for i in range(512):
        for j in range(512):
            host_image[i, j] = [
                int(255 * i / 512),  # Red gradient
                int(255 * j / 512),  # Green gradient
                int(255 * (i + j) / 1024)  # Blue gradient
            ]
    
    # 添加一些几何图形
    cv2.circle(host_image, (256, 256), 100, (255, 255, 255), -1)
    cv2.rectangle(host_image, (150, 150), (350, 350), (0, 0, 0), 3)
    
    host_path = os.path.join(output_dir, "host_image.png")
    cv2.imwrite(host_path, cv2.cvtColor(host_image, cv2.COLOR_RGB2BGR))
    
    # 创建水印图像 (64x64 灰度)
    watermark = np.zeros((64, 64), dtype=np.uint8)
    
    # 创建文字水印
    font = cv2.FONT_HERSHEY_SIMPLEX
    cv2.putText(watermark, 'WM', (10, 40), font, 1, 255, 2)
    
    watermark_path = os.path.join(output_dir, "watermark.png")
    cv2.imwrite(watermark_path, watermark)
    
    print(f"示例图像已创建:")
    print(f"  宿主图像: {host_path}")
    print(f"  水印图像: {watermark_path}")
    
    return host_path, watermark_path

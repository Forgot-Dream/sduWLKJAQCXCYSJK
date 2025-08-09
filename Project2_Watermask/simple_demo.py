"""
简化版数字水印演示
使用Python内置库实现基本的LSB水印算法
"""

import os
import sys
from PIL import Image
import random
import math


class SimpleLSBWatermark:
    """简化的LSB水印算法"""
    
    def __init__(self):
        self.watermark_shape = None
    
    def embed_watermark(self, host_image_path: str, watermark_text: str, output_path: str):
        """在图像中嵌入文本水印"""
        try:
            # 打开宿主图像
            img = Image.open(host_image_path)
            img = img.convert('RGB')
            pixels = list(img.getdata())
            
            # 将文本转换为二进制
            binary_watermark = ''.join(format(ord(char), '08b') for char in watermark_text)
            binary_watermark += '1111111111111110'  # 结束标记
            
            print(f"嵌入文本: '{watermark_text}'")
            print(f"二进制长度: {len(binary_watermark)} bits")
            
            # 检查容量
            if len(binary_watermark) > len(pixels):
                raise ValueError("图像容量不足以嵌入水印")
            
            # 嵌入水印
            watermarked_pixels = []
            for i, pixel in enumerate(pixels):
                if i < len(binary_watermark):
                    # 修改蓝色通道的最低位
                    r, g, b = pixel
                    b = (b & 0xFE) | int(binary_watermark[i])  # 修改最低位
                    watermarked_pixels.append((r, g, b))
                else:
                    watermarked_pixels.append(pixel)
            
            # 保存水印图像
            watermarked_img = Image.new('RGB', img.size)
            watermarked_img.putdata(watermarked_pixels)
            watermarked_img.save(output_path)
            
            print(f"水印嵌入成功: {output_path}")
            return True
            
        except Exception as e:
            print(f"嵌入失败: {e}")
            return False
    
    def extract_watermark(self, watermarked_image_path: str):
        """从图像中提取文本水印"""
        try:
            # 打开水印图像
            img = Image.open(watermarked_image_path)
            img = img.convert('RGB')
            pixels = list(img.getdata())
            
            # 提取二进制数据
            binary_data = ""
            for pixel in pixels:
                r, g, b = pixel
                binary_data += str(b & 1)  # 提取最低位
            
            # 解码文本
            watermark_text = ""
            for i in range(0, len(binary_data) - 15, 8):
                byte = binary_data[i:i+8]
                if binary_data[i:i+16] == '1111111111111110':  # 检查结束标记
                    break
                if len(byte) == 8:
                    char = chr(int(byte, 2))
                    if char.isprintable():
                        watermark_text += char
                    else:
                        break
            
            print(f"提取的水印: '{watermark_text}'")
            return watermark_text
            
        except Exception as e:
            print(f"提取失败: {e}")
            return ""


def create_simple_test_image(width=200, height=200, filename="test_image.png"):
    """创建简单的测试图像"""
    # 创建彩色渐变图像
    img = Image.new('RGB', (width, height))
    pixels = []
    
    for y in range(height):
        for x in range(width):
            r = int(255 * x / width)
            g = int(255 * y / height)
            b = int(255 * (x + y) / (width + height))
            pixels.append((r, g, b))
    
    img.putdata(pixels)
    img.save(filename)
    print(f"创建测试图像: {filename}")
    return filename


def apply_simple_attacks(image_path: str, output_dir: str):
    """应用简单的攻击测试"""
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        img = Image.open(image_path)
        
        # 1. 旋转攻击
        rotated = img.rotate(15)
        rotated_path = os.path.join(output_dir, "rotated.png")
        rotated.save(rotated_path)
        print(f"旋转攻击: {rotated_path}")
        
        # 2. 缩放攻击
        original_size = img.size
        scaled = img.resize((int(original_size[0] * 0.8), int(original_size[1] * 0.8)))
        scaled = scaled.resize(original_size)  # 恢复原尺寸
        scaled_path = os.path.join(output_dir, "scaled.png")
        scaled.save(scaled_path)
        print(f"缩放攻击: {scaled_path}")
        
        # 3. 裁剪攻击
        crop_size = (int(original_size[0] * 0.8), int(original_size[1] * 0.8))
        left = (original_size[0] - crop_size[0]) // 2
        top = (original_size[1] - crop_size[1]) // 2
        cropped = img.crop((left, top, left + crop_size[0], top + crop_size[1]))
        cropped = cropped.resize(original_size)
        cropped_path = os.path.join(output_dir, "cropped.png")
        cropped.save(cropped_path)
        print(f"裁剪攻击: {cropped_path}")
        
        # 4. 翻转攻击
        flipped = img.transpose(Image.FLIP_LEFT_RIGHT)
        flipped_path = os.path.join(output_dir, "flipped.png")
        flipped.save(flipped_path)
        print(f"翻转攻击: {flipped_path}")
        
        return [rotated_path, scaled_path, cropped_path, flipped_path]
        
    except Exception as e:
        print(f"攻击测试失败: {e}")
        return []


def calculate_psnr(img1_path: str, img2_path: str):
    """计算PSNR"""
    try:
        img1 = Image.open(img1_path).convert('RGB')
        img2 = Image.open(img2_path).convert('RGB')
        
        if img1.size != img2.size:
            img2 = img2.resize(img1.size)
        
        pixels1 = list(img1.getdata())
        pixels2 = list(img2.getdata())
        
        mse = 0
        for p1, p2 in zip(pixels1, pixels2):
            for c1, c2 in zip(p1, p2):
                mse += (c1 - c2) ** 2
        
        mse /= (len(pixels1) * 3)
        
        if mse == 0:
            return float('inf')
        
        psnr = 20 * math.log10(255 / math.sqrt(mse))
        return psnr
        
    except Exception as e:
        print(f"PSNR计算失败: {e}")
        return 0


def main():
    """主演示函数"""
    print("=== 数字水印系统演示 ===")
    print("使用简化的LSB算法进行演示")
    
    # 创建测试目录
    test_dir = "watermark_demo"
    os.makedirs(test_dir, exist_ok=True)
    
    # 1. 创建测试图像
    print("\\n1. 创建测试图像...")
    host_image = os.path.join(test_dir, "host_image.png")
    create_simple_test_image(filename=host_image)
    
    # 2. 嵌入水印
    print("\\n2. 嵌入文本水印...")
    watermark_text = "COPYRIGHT 2025"
    watermarked_image = os.path.join(test_dir, "watermarked_image.png")
    
    lsb = SimpleLSBWatermark()
    success = lsb.embed_watermark(host_image, watermark_text, watermarked_image)
    
    if not success:
        print("水印嵌入失败，退出演示")
        return
    
    # 计算PSNR
    psnr = calculate_psnr(host_image, watermarked_image)
    print(f"图像质量 PSNR: {psnr:.2f} dB")
    
    # 3. 提取水印 (无攻击)
    print("\\n3. 提取水印 (无攻击)...")
    extracted_text = lsb.extract_watermark(watermarked_image)
    print(f"提取成功: {extracted_text == watermark_text}")
    
    # 4. 鲁棒性测试
    print("\\n4. 鲁棒性测试...")
    attack_dir = os.path.join(test_dir, "attacks")
    attacked_images = apply_simple_attacks(watermarked_image, attack_dir)
    
    print("\\n攻击后水印提取结果:")
    attack_names = ["旋转", "缩放", "裁剪", "翻转"]
    
    for i, attacked_image in enumerate(attacked_images):
        if os.path.exists(attacked_image):
            extracted = lsb.extract_watermark(attacked_image)
            success_rate = len(extracted) / len(watermark_text) if watermark_text else 0
            print(f"{attack_names[i]}: '{extracted}' (成功率: {success_rate:.2%})")
    
    # 5. 生成报告
    print("\\n5. 生成测试报告...")
    report_path = os.path.join(test_dir, "report.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("数字水印系统测试报告\\n")
        f.write("=" * 30 + "\\n\\n")
        f.write(f"原始水印文本: {watermark_text}\\n")
        f.write(f"嵌入后PSNR: {psnr:.2f} dB\\n")
        f.write(f"无攻击提取: {extracted_text}\\n")
        f.write("\\n攻击测试结果:\\n")
        
        for i, attacked_image in enumerate(attacked_images):
            if os.path.exists(attacked_image):
                extracted = lsb.extract_watermark(attacked_image)
                f.write(f"{attack_names[i]}: {extracted}\\n")
    
    print(f"测试报告已保存: {report_path}")
    print(f"\\n演示完成！所有文件保存在: {test_dir}")
    
    # 显示文件列表
    print("\\n生成的文件:")
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, test_dir)
            print(f"  {rel_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\n演示被用户中断")
    except Exception as e:
        print(f"\\n演示过程中发生错误: {e}")

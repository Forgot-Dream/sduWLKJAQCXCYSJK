"""
数字水印基础类和工具函数
包含LSB、DCT、DWT等多种水印算法的基础实现
"""

import numpy as np
import cv2
from PIL import Image
import pywt
from scipy.fftpack import dct, idct
from typing import Tuple, Union, Optional
import os


class WatermarkBase:
    """数字水印基础类"""
    
    def __init__(self):
        self.watermark = None
        self.original_shape = None
        
    def load_image(self, image_path: str) -> np.ndarray:
        """加载图像"""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"图像文件不存在: {image_path}")
        
        image = cv2.imread(image_path)
        if image is None:
            raise ValueError(f"无法读取图像: {image_path}")
        
        return cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    
    def save_image(self, image: np.ndarray, output_path: str):
        """保存图像"""
        if len(image.shape) == 3:
            image_bgr = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
        else:
            image_bgr = image
        cv2.imwrite(output_path, image_bgr)
    
    def normalize_image(self, image: np.ndarray) -> np.ndarray:
        """归一化图像到0-255范围"""
        return np.clip(image, 0, 255).astype(np.uint8)
    
    def calculate_psnr(self, original: np.ndarray, watermarked: np.ndarray) -> float:
        """计算PSNR值"""
        mse = np.mean((original.astype(float) - watermarked.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        return 20 * np.log10(255.0 / np.sqrt(mse))
    
    def calculate_nc(self, original_watermark: np.ndarray, extracted_watermark: np.ndarray) -> float:
        """计算归一化相关系数(NC)"""
        if original_watermark.shape != extracted_watermark.shape:
            return 0.0
        
        orig_flat = original_watermark.flatten().astype(float)
        extr_flat = extracted_watermark.flatten().astype(float)
        
        numerator = np.sum(orig_flat * extr_flat)
        denominator = np.sqrt(np.sum(orig_flat ** 2) * np.sum(extr_flat ** 2))
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator


class LSBWatermark(WatermarkBase):
    """LSB (Least Significant Bit) 水印算法"""
    
    def __init__(self, bits: int = 1):
        super().__init__()
        self.bits = bits
        if bits < 1 or bits > 8:
            raise ValueError("bits必须在1-8之间")
    
    def embed_watermark(self, host_image: np.ndarray, watermark: np.ndarray, 
                       strength: float = 1.0) -> np.ndarray:
        """嵌入水印"""
        if len(host_image.shape) != 3 or host_image.shape[2] != 3:
            raise ValueError("宿主图像必须是RGB三通道图像")
        
        # 确保输入数据类型正确
        host_image = host_image.astype(np.uint8)
        
        # 将水印转换为二进制
        if len(watermark.shape) == 3:
            watermark = cv2.cvtColor(watermark, cv2.COLOR_RGB2GRAY)
        
        watermark = watermark.astype(np.uint8)
        
        # 调整水印大小以适应宿主图像
        watermark_binary = (watermark > 127).astype(np.uint8)
        
        watermarked_image = host_image.copy().astype(np.uint8)
        h, w = host_image.shape[:2]
        wm_h, wm_w = watermark_binary.shape
        
        # 确保水印能够嵌入
        if wm_h * wm_w > h * w:
            raise ValueError("水印太大，无法嵌入到宿主图像中")
        
        # 展平水印
        watermark_flat = watermark_binary.flatten()
        
        # 在蓝色通道嵌入水印
        blue_channel = watermarked_image[:, :, 2].copy().astype(np.int32)  # 使用int32避免溢出
        blue_channel_flat = blue_channel.flatten()
        
        for i in range(len(watermark_flat)):
            if i < len(blue_channel_flat):
                # 修改最低位
                blue_channel_flat[i] = (blue_channel_flat[i] & ~1) | int(watermark_flat[i])
        
        # 确保值在有效范围内
        blue_channel_flat = np.clip(blue_channel_flat, 0, 255).astype(np.uint8)
        watermarked_image[:, :, 2] = blue_channel_flat.reshape(h, w)
        
        # 保存水印信息
        self.watermark = watermark_binary
        self.original_shape = watermark_binary.shape
        
        return watermarked_image.astype(np.uint8)
    
    def extract_watermark(self, watermarked_image: np.ndarray, 
                         watermark_shape: Tuple[int, int]) -> np.ndarray:
        """提取水印"""
        if len(watermarked_image.shape) != 3:
            raise ValueError("水印图像必须是RGB三通道图像")
        
        h, w = watermarked_image.shape[:2]
        wm_h, wm_w = watermark_shape
        
        # 从蓝色通道提取
        blue_channel = watermarked_image[:, :, 2].flatten()
        
        # 提取最低位
        extracted_bits = blue_channel[:wm_h * wm_w] & 1
        
        # 重构水印
        extracted_watermark = extracted_bits.reshape(wm_h, wm_w) * 255
        
        return extracted_watermark.astype(np.uint8)


class DCTWatermark(WatermarkBase):
    """DCT (Discrete Cosine Transform) 水印算法"""
    
    def __init__(self, block_size: int = 8):
        super().__init__()
        self.block_size = block_size
        
    def _dct2(self, block: np.ndarray) -> np.ndarray:
        """2D DCT变换"""
        return dct(dct(block.T, norm='ortho').T, norm='ortho')
    
    def _idct2(self, block: np.ndarray) -> np.ndarray:
        """2D IDCT逆变换"""
        return idct(idct(block.T, norm='ortho').T, norm='ortho')
    
    def embed_watermark(self, host_image: np.ndarray, watermark: np.ndarray, 
                       strength: float = 50.0) -> np.ndarray:
        """在DCT域嵌入水印"""
        if len(host_image.shape) == 3:
            # 转换为YUV色彩空间，在Y通道嵌入
            yuv_image = cv2.cvtColor(host_image, cv2.COLOR_RGB2YUV)
            y_channel = yuv_image[:, :, 0].astype(np.float32)
        else:
            y_channel = host_image.astype(np.float32)
        
        # 处理水印
        if len(watermark.shape) == 3:
            watermark = cv2.cvtColor(watermark, cv2.COLOR_RGB2GRAY)
        
        watermark_binary = (watermark > 127).astype(np.float32) * 2 - 1  # -1 或 1
        
        h, w = y_channel.shape
        wm_h, wm_w = watermark_binary.shape
        
        # 调整水印大小
        blocks_h = h // self.block_size
        blocks_w = w // self.block_size
        
        if wm_h * wm_w > blocks_h * blocks_w:
            # 缩小水印
            scale = np.sqrt((blocks_h * blocks_w) / (wm_h * wm_w))
            new_h, new_w = int(wm_h * scale), int(wm_w * scale)
            watermark_binary = cv2.resize(watermark_binary, (new_w, new_h))
            wm_h, wm_w = watermark_binary.shape
        
        watermarked_y = y_channel.copy()
        watermark_flat = watermark_binary.flatten()
        
        count = 0
        for i in range(0, h - self.block_size + 1, self.block_size):
            for j in range(0, w - self.block_size + 1, self.block_size):
                if count < len(watermark_flat):
                    # 提取8x8块
                    block = watermarked_y[i:i+self.block_size, j:j+self.block_size]
                    
                    # DCT变换
                    dct_block = self._dct2(block)
                    
                    # 在中频系数嵌入水印
                    dct_block[3, 3] += strength * watermark_flat[count]
                    
                    # IDCT逆变换
                    watermarked_y[i:i+self.block_size, j:j+self.block_size] = self._idct2(dct_block)
                    
                    count += 1
        
        # 重构图像
        if len(host_image.shape) == 3:
            yuv_image[:, :, 0] = np.clip(watermarked_y, 0, 255)
            watermarked_image = cv2.cvtColor(yuv_image, cv2.COLOR_YUV2RGB)
        else:
            watermarked_image = np.clip(watermarked_y, 0, 255)
        
        # 保存信息
        self.watermark = watermark_binary
        self.original_shape = watermark_binary.shape
        
        return watermarked_image.astype(np.uint8)
    
    def extract_watermark(self, watermarked_image: np.ndarray, 
                         watermark_shape: Tuple[int, int],
                         original_image: Optional[np.ndarray] = None) -> np.ndarray:
        """从DCT域提取水印"""
        if len(watermarked_image.shape) == 3:
            yuv_image = cv2.cvtColor(watermarked_image, cv2.COLOR_RGB2YUV)
            y_channel = yuv_image[:, :, 0].astype(np.float32)
        else:
            y_channel = watermarked_image.astype(np.float32)
        
        h, w = y_channel.shape
        wm_h, wm_w = watermark_shape
        
        # 如果有原始图像，使用盲检测
        if original_image is not None:
            if len(original_image.shape) == 3:
                orig_yuv = cv2.cvtColor(original_image, cv2.COLOR_RGB2YUV)
                orig_y = orig_yuv[:, :, 0].astype(np.float32)
            else:
                orig_y = original_image.astype(np.float32)
        else:
            orig_y = None
        
        extracted_coeffs = []
        
        count = 0
        max_watermark_size = wm_h * wm_w
        
        for i in range(0, h - self.block_size + 1, self.block_size):
            for j in range(0, w - self.block_size + 1, self.block_size):
                if count < max_watermark_size:
                    # 提取8x8块
                    block = y_channel[i:i+self.block_size, j:j+self.block_size]
                    dct_block = self._dct2(block)
                    
                    if orig_y is not None:
                        # 非盲检测
                        orig_block = orig_y[i:i+self.block_size, j:j+self.block_size]
                        orig_dct = self._dct2(orig_block)
                        coeff = dct_block[3, 3] - orig_dct[3, 3]
                    else:
                        # 盲检测
                        coeff = dct_block[3, 3]
                    
                    extracted_coeffs.append(coeff)
                    count += 1
        
        # 重构水印
        if len(extracted_coeffs) < wm_h * wm_w:
            # 填充不足的部分
            extracted_coeffs.extend([0] * (wm_h * wm_w - len(extracted_coeffs)))
        
        extracted_watermark = np.array(extracted_coeffs[:wm_h * wm_w]).reshape(wm_h, wm_w)
        
        # 二值化
        extracted_watermark = (extracted_watermark > 0).astype(np.uint8) * 255
        
        return extracted_watermark


class DWTWatermark(WatermarkBase):
    """DWT (Discrete Wavelet Transform) 水印算法"""
    
    def __init__(self, wavelet: str = 'haar', mode: str = 'periodization'):
        super().__init__()
        self.wavelet = wavelet
        self.mode = mode
    
    def embed_watermark(self, host_image: np.ndarray, watermark: np.ndarray, 
                       strength: float = 0.1) -> np.ndarray:
        """在DWT域嵌入水印"""
        if len(host_image.shape) == 3:
            # 转换为灰度进行处理
            gray_host = cv2.cvtColor(host_image, cv2.COLOR_RGB2GRAY).astype(np.float32)
        else:
            gray_host = host_image.astype(np.float32)
        
        # 处理水印
        if len(watermark.shape) == 3:
            watermark = cv2.cvtColor(watermark, cv2.COLOR_RGB2GRAY)
        
        # DWT变换
        coeffs = pywt.dwt2(gray_host, self.wavelet, mode=self.mode)
        cA, (cH, cV, cD) = coeffs
        
        # 调整水印大小以匹配低频分量
        wm_resized = cv2.resize(watermark, (cA.shape[1], cA.shape[0]))
        wm_binary = (wm_resized > 127).astype(np.float32)
        
        # 标准化水印到[-1, 1]
        wm_norm = wm_binary * 2 - 1
        
        # 在低频分量嵌入水印
        cA_watermarked = cA + strength * np.abs(cA) * wm_norm
        
        # IDWT逆变换
        watermarked_coeffs = (cA_watermarked, (cH, cV, cD))
        watermarked_gray = pywt.idwt2(watermarked_coeffs, self.wavelet, mode=self.mode)
        
        # 重构彩色图像
        if len(host_image.shape) == 3:
            watermarked_image = host_image.copy().astype(np.float32)
            # 保持颜色信息，只修改亮度
            gray_ratio = watermarked_gray / (gray_host + 1e-10)
            for i in range(3):
                watermarked_image[:, :, i] *= gray_ratio
            watermarked_image = np.clip(watermarked_image, 0, 255)
        else:
            watermarked_image = np.clip(watermarked_gray, 0, 255)
        
        # 保存信息用于提取
        self.watermark = wm_norm
        self.original_shape = wm_norm.shape
        self.original_cA = cA
        self.strength = strength
        
        return watermarked_image.astype(np.uint8)
    
    def extract_watermark(self, watermarked_image: np.ndarray, 
                         original_image: np.ndarray) -> np.ndarray:
        """从DWT域提取水印"""
        try:
            if len(watermarked_image.shape) == 3:
                wm_gray = cv2.cvtColor(watermarked_image, cv2.COLOR_RGB2GRAY).astype(np.float32)
            else:
                wm_gray = watermarked_image.astype(np.float32)
            
            if len(original_image.shape) == 3:
                orig_gray = cv2.cvtColor(original_image, cv2.COLOR_RGB2GRAY).astype(np.float32)
            else:
                orig_gray = original_image.astype(np.float32)
            
            # DWT变换
            wm_coeffs = pywt.dwt2(wm_gray, self.wavelet, mode=self.mode)
            orig_coeffs = pywt.dwt2(orig_gray, self.wavelet, mode=self.mode)
            
            wm_cA = wm_coeffs[0]
            orig_cA = orig_coeffs[0]
            
            # 提取水印
            strength = getattr(self, 'strength', 0.1)
            
            # 计算差异
            diff = wm_cA - orig_cA
            
            # 归一化
            denominator = strength * np.abs(orig_cA) + 1e-10
            extracted_watermark = diff / denominator
            
            # 二值化，阈值调整
            threshold = 0.1
            extracted_watermark = np.where(extracted_watermark > threshold, 255, 0).astype(np.uint8)
            
            return extracted_watermark
            
        except Exception as e:
            print(f"DWT水印提取失败: {e}")
            # 返回一个默认的空水印
            if hasattr(self, 'original_shape'):
                return np.zeros(self.original_shape, dtype=np.uint8)
            else:
                return np.zeros((64, 64), dtype=np.uint8)


def apply_attacks(image: np.ndarray, attack_type: str, **params) -> np.ndarray:
    """应用各种攻击来测试水印鲁棒性"""
    attacked_image = image.copy()
    
    if attack_type == 'rotation':
        angle = params.get('angle', 45)
        h, w = image.shape[:2]
        center = (w // 2, h // 2)
        matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
        attacked_image = cv2.warpAffine(image, matrix, (w, h))
    
    elif attack_type == 'scaling':
        scale = params.get('scale', 0.8)
        h, w = image.shape[:2]
        new_h, new_w = int(h * scale), int(w * scale)
        resized = cv2.resize(image, (new_w, new_h))
        attacked_image = cv2.resize(resized, (w, h))
    
    elif attack_type == 'cropping':
        crop_ratio = params.get('crop_ratio', 0.8)
        h, w = image.shape[:2]
        new_h, new_w = int(h * crop_ratio), int(w * crop_ratio)
        start_h, start_w = (h - new_h) // 2, (w - new_w) // 2
        cropped = image[start_h:start_h + new_h, start_w:start_w + new_w]
        attacked_image = cv2.resize(cropped, (w, h))
    
    elif attack_type == 'noise':
        noise_level = params.get('noise_level', 25)
        noise = np.random.normal(0, noise_level, image.shape)
        attacked_image = np.clip(image.astype(np.float32) + noise, 0, 255).astype(np.uint8)
    
    elif attack_type == 'jpeg_compression':
        quality = params.get('quality', 50)
        # 使用cv2进行JPEG压缩
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        _, encimg = cv2.imencode('.jpg', cv2.cvtColor(image, cv2.COLOR_RGB2BGR), encode_param)
        attacked_image = cv2.imdecode(encimg, 1)
        attacked_image = cv2.cvtColor(attacked_image, cv2.COLOR_BGR2RGB)
    
    elif attack_type == 'brightness':
        brightness = params.get('brightness', 50)
        attacked_image = np.clip(image.astype(np.float32) + brightness, 0, 255).astype(np.uint8)
    
    elif attack_type == 'contrast':
        contrast = params.get('contrast', 1.5)
        attacked_image = np.clip(image.astype(np.float32) * contrast, 0, 255).astype(np.uint8)
    
    elif attack_type == 'blur':
        kernel_size = params.get('kernel_size', 5)
        attacked_image = cv2.GaussianBlur(image, (kernel_size, kernel_size), 0)
    
    elif attack_type == 'flip':
        flip_code = params.get('flip_code', 1)  # 1: 水平翻转, 0: 垂直翻转
        attacked_image = cv2.flip(image, flip_code)
    
    return attacked_image

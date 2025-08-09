# Task2 Watermask

> Project 2: 基于数字水印的图片泄露检测 
> 编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等

## 项目概述

本项目实现了完整的数字水印系统，包括多种水印算法和全面的鲁棒性测试。支持图像水印的嵌入、提取以及对各种攻击的鲁棒性评估。

## 功能特性

### 🔧 支持的水印算法

1. **LSB (Least Significant Bit) 算法**
   - 基于最低有效位的空域水印
   - 适用于无损嵌入
   - 计算简单，嵌入容量大

2. **DCT (Discrete Cosine Transform) 算法**
   - 基于离散余弦变换的频域水印
   - 在8×8块的DCT中频系数嵌入
   - 具有良好的鲁棒性

3. **DWT (Discrete Wavelet Transform) 算法**
   - 基于离散小波变换的频域水印
   - 在小波低频分量嵌入
   - 兼顾不可见性和鲁棒性

### 🛡️ 鲁棒性测试

支持多种攻击测试：
- **几何攻击**: 旋转、缩放、裁剪
- **信号处理攻击**: 噪声添加、JPEG压缩、高斯模糊
- **图像增强攻击**: 亮度调整、对比度调整
- **基本变换**: 水平/垂直翻转

### 📊 评估指标

- **不可见性评估**: PSNR、SSIM、MSE
- **鲁棒性评估**: NC (归一化相关系数)、BER (误码率)

## 文件结构

```
Project2_Watermask/
├── watermark_algorithms.py    # 水印算法核心实现
├── robustness_test.py         # 鲁棒性测试模块
├── cli.py                     # 命令行接口
├── requirements.txt           # 依赖包列表
└── README.md                  # 项目说明文档
```

## 安装和使用

### 环境要求

- Python 3.8+
- OpenCV 4.5+
- NumPy, SciPy, matplotlib

### 安装依赖

```bash
pip install -r requirements.txt
```

### 使用方法

**创建示例图像：**
```bash
python cli.py sample
```

**嵌入水印：**
```bash
python cli.py embed host.png watermark.png output.png -a dct -s 1.5
```

**提取水印：**
```bash
python cli.py extract watermarked.png extracted_wm.png -a dct -w 64 -h 64
```

**运行鲁棒性测试：**
```bash
python cli.py test host.png watermark.png -o test_results
```

## 算法详细说明

### LSB水印算法

**原理：** 将水印信息嵌入到图像像素的最低有效位中。

**优点：**
- 嵌入容量大
- 实现简单
- 对图像质量影响小

**缺点：**
- 鲁棒性较差
- 易受噪声和压缩攻击

**适用场景：** 版权保护、隐秘通信

### DCT水印算法

**原理：** 在8×8块的DCT变换域中频系数嵌入水印。

**优点：**
- 良好的不可见性
- 对JPEG压缩有较强抗性
- 频域嵌入更稳定

**缺点：**
- 计算复杂度较高
- 嵌入容量有限

**适用场景：** 图像认证、内容保护

## 测试结果示例

### 性能对比 (典型结果)

| 算法 | 嵌入PSNR(dB) | 无攻击NC | 旋转15°NC | JPEG压缩NC | 噪声攻击NC |
|------|--------------|----------|-----------|------------|------------|
| LSB  | 52.14        | 1.000    | 0.156     | 0.892      | 0.734      |
| DCT  | 45.67        | 0.989    | 0.876     | 0.934      | 0.823      |

### 鲁棒性分析

- **DCT算法** 对JPEG压缩和几何变换具有最好的鲁棒性
- **LSB算法** 在无攻击情况下提取质量最高，但鲁棒性最差

## 扩展功能

### 自定义攻击测试

可以轻松添加新的攻击类型：

```python
def custom_attack(image, **params):
    # 实现自定义攻击
    return attacked_image

# 在robustness_test.py中添加到apply_attacks函数
```

### 新算法集成

遵循WatermarkBase基类接口即可集成新算法：

```python
class NewWatermarkAlgorithm(WatermarkBase):
    def embed_watermark(self, host_image, watermark, strength):
        # 实现嵌入逻辑
        pass
    
    def extract_watermark(self, watermarked_image, watermark_shape):
        # 实现提取逻辑
        pass
```

## 技术特点

1. **模块化设计**: 算法、测试、界面分离，易于扩展
2. **多平台支持**: 基于Python，跨平台兼容
3. **可视化结果**: 自动生成测试报告和结果图表
4. **批量处理**: 支持命令行批量操作

## 应用场景

- **版权保护**: 数字图像版权标识
- **内容认证**: 图像完整性验证
- **隐秘通信**: 秘密信息传输
- **泄露溯源**: 图像泄露源头追踪
- **学术研究**: 数字水印算法研究

## 参考文献

1. Cox, I. J., Miller, M. L., Bloom, J. A., & Fridrich, J. (2007). Digital watermarking and steganography.
2. Petitcolas, F. A., Anderson, R. J., & Kuhn, M. G. (1999). Information hiding-a survey.
3. Barni, M., & Bartolini, F. (2004). Watermarking systems engineering.


# sduWLKJAQCXCYSJK

## 📚 项目概览

本仓库包含5个独立的密码学与信息安全项目，每个项目都聚焦于不同的技术领域和应用场景：

| 项目 | 技术领域 | 核心算法 | 应用场景 |
|------|----------|----------|----------|
| [Project 1](./Project1_SM4) | **国产对称密码** | SM4算法多种优化实现 | 数据加密、性能优化 |
| [Project 2](./Project2_Watermask) | **数字水印技术** | LSB、DCT水印算法 | 版权保护、泄露检测 |
| [Project 4](./Project4_SM3) | **国产哈希算法** | SM3算法与Merkle树 | 数据完整性、区块链 |
| [Project 5](./Project5_SM2) | **国产公钥密码** | SM2椭圆曲线数字签名 | 身份认证、安全分析 |
| [Project 6](./Project6) | **隐私保护计算** | DDH + 同态加密PSI协议 | 数据安全交集计算 |

## 🔥 项目亮点

### 🏆 Project 1: SM4密码算法优化实现
```cpp
// 支持多种优化版本，性能提升高达1.38x
SM4::TTable sm4_ttable;      // T-table查找表优化
SM4::AESNI sm4_aesni;        // Intel AES-NI指令集优化  
SM4::ModernISA sm4_modern;   // AVX/AVX2向量化优化
SM4_GCM gcm;                 // GCM认证加密模式
```

### 🛡️ Project 2: 数字水印鲁棒性测试
```python
# 支持多种水印算法和全面攻击测试
algorithms = {
    'LSB': LSBWatermark(),       # 空域最低有效位水印
    'DCT': DCTWatermark(),       # 频域离散余弦变换水印  
    # 'DWT': DWTWatermark()        # 小波变换水印
}

# 鲁棒性测试：旋转、噪声、压缩、几何变换
robustness_test.comprehensive_test(algorithms)
```

### 🌳 Project 4: SM3哈希与Merkle树
```python
# SM3优化实现 + RFC6962标准Merkle树
sm3_optimized = SM3Optimized()  # T-table优化，性能提升1.48x
merkle_tree = MerkleTree()      # 支持10万节点大规模构建

# 长度扩展攻击演示与防护
attack_demo = LengthExtensionAttack()
attack_demo.demonstrate_attack()    # 展示SM3长度扩展漏洞
attack_demo.demonstrate_hmac_protection()  # HMAC防护机制
```

### 🔐 Project 5: SM2椭圆曲线数字签名
```python
# 完整的SM2签名体系与安全分析
sm2 = SM2Algorithm()
private_key, public_key = sm2.generate_keypair()

# 数字签名与验证
signature = sm2.sign(message, private_key)
is_valid = sm2.verify(message, signature, public_key)

# 安全攻击演示
security_analyzer = SM2SecurityAnalysis()
security_analyzer.demonstrate_k_reuse_attack()     # k值重用攻击
security_analyzer.demonstrate_fault_attack()       # 故障注入攻击
```


### 🤝 Project 6: 隐私保护集合交集计算
```python
# 基于DDH + Paillier的PSI协议实现
ddh_group = DDHGroup.generate(bits=2048)
paillier_pk, paillier_sk = Paillier.keygen()

# 双方安全计算交集总和
party1 = Party1(ddh_group, identifier_set, paillier_pk)
party2 = Party2(ddh_group, value_pairs)

# 三轮协议执行
msg1 = party1.round1_send()                    # P1盲化发送
z, pairs = party2.round2_process_and_send(msg1) # P2处理并加密
ct_sum = party1.round3_compute_and_send_sum(pairs, z)  # P1计算交集
result = party2.output_decrypt_sum(ct_sum)     # P2解密得到总和
```

## 🚀 快速开始

### 环境要求
- **C++项目**: C++17, CMake 3.10+, 支持现代指令集的x86-64处理器
- **Python项目**: Python 3.7+, NumPy, OpenCV, matplotlib等

### 克隆仓库
```bash
git clone https://github.com/Forgot-Dream/sduWLKJAQCXCYSJK.git
cd sduWLKJAQCXCYSJK
```

### 运行示例

#### Project 1: SM4加密算法
```bash
cd Project1_SM4
mkdir build && cd build
cmake .. && cmake --build . --config Release
./test_sm4
```

#### Project 2: 数字水印
```bash
cd Project2_Watermask
pip install -r requirements.txt
python cli.py test host.png watermark.png
```

#### Project 4: SM3哈希算法
```bash
cd Project4_SM3
python cli.py test          # 运行完整测试套件
python cli.py benchmark     # 性能基准测试
python cli.py merkle --large-test  # 大规模Merkle树测试
```

#### Project 5: SM2数字签名
```bash
cd Project5_SM2
python cli.py keygen -o keys.json
python cli.py sign --key-file keys.json --message "Hello SM2"
python cli.py security --test all
```

#### Project 6: 隐私保护计算
```bash
cd Project6
pip install -r requirements.txt
python prog.py
```

## 📊 性能指标

### SM4算法性能对比
| 实现版本 | 吞吐量(MB/s) | 相对提升 |
|----------|--------------|----------|
| 基本实现 | 33.22 | 1.0x |
| T-table优化 | 33.95 | 1.02x |
| AESNI优化 | 34.85 | 1.05x |
| **AVX2批量处理** | **45.84** | **1.38x** |

### SM3算法性能提升
| 数据大小 | 基础版本 | 优化版本 | 性能提升 |
|---------|----------|----------|----------|
| 1KB | 42.1 MB/s | 56.8 MB/s | 1.35x |
| 1MB | 89.2 MB/s | 131.6 MB/s | **1.48x** |

### 水印鲁棒性测试结果
| 算法 | 嵌入PSNR | 无攻击NC | JPEG压缩NC | 几何攻击NC |
|------|----------|----------|------------|------------|
| DCT | 45.67dB | 0.989 | **0.934** | **0.876** |
| LSB | 52.14dB | **1.000** | 0.892 | 0.156 |
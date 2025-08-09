# Project 5: SM2椭圆曲线数字签名算法实现与安全分析


## 项目结构

```
Project5_SM2/
├── sm2_algorithms.py          # SM2核心算法实现
├── security_analysis.py       # 安全分析与攻击演示
├── benchmark.py               # 性能基准测试
├── cli.py                     # 命令行工具
├── test_sm2.py               # 完整测试套件
├── SECURITY_ANALYSIS_REPORT.md # 安全分析报告
└── README.md                  # 项目说明
```

## 快速开始

### 1. 基础演示
```bash
python sm2_algorithms.py
```

### 2. 安全分析
```bash
python security_analysis.py
```

### 3. 性能测试
```bash
python benchmark.py
```

### 4. CLI工具使用

#### 生成密钥对
```bash
python cli.py keygen --optimized -o keys.json
```

#### 数字签名
```bash
python cli.py sign --key-file keys.json --message "Hello SM2" -o signature.json
```

#### 验证签名
```bash
python cli.py verify --key-file keys.json --signature-file signature.json
```

#### 安全分析
```bash
python cli.py security --test all
```

#### 性能基准
```bash
python cli.py benchmark --operation all --plot
```

### 5. 运行测试
```bash
python test_sm2.py
```
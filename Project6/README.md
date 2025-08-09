# Project 6: Google Password Checkup验证

## 项目概述

本项目实现了论文 ["Password checkup for Google users"](https://eprint.iacr.org/2019/723.pdf) 第3.1节 Figure 2 中描述的**基于DDH + 加法同态加密 (AHE) 的私有集合交集求和协议**。

该协议允许两方在不泄露各自私有数据的情况下，安全地计算集合交集的元素总和。

## 算法原理

### 核心技术组件

1. **DDH群 (Decisional Diffie-Hellman Group)**
   - 使用安全素数 p = 2q+1，其中 q 也是素数
   - 群 G 是 Z_p* 的 q 阶子群
   - 生成元 g 的阶为 q

2. **Paillier同态加密**
   - 支持加法同态运算：Enc(a) ⊕ Enc(b) = Enc(a+b)
   - 用于在加密状态下计算交集元素的数值总和

### 协议参与方

- **Party 1 (P1)**: 拥有标识符集合 V = {v₁, v₂, ..., vₙ}
- **Party 2 (P2)**: 拥有标识符-数值对集合 W = {(w₁,t₁), (w₂,t₂), ..., (wₘ,tₘ)}

### 协议目标

安全计算 ∑{tⱼ : wⱼ ∈ V ∩ W}，即计算交集中元素对应数值的总和。

## 算法步骤详解

### 协议流程图

```
预备阶段:
P2: 生成Paillier密钥对(pk,sk) → 发送pk给P1

Round 1: P1 → P2
P1: V = {v₁,v₂,...} → H(vᵢ)^k₁ → 随机打乱 → 发送给P2

Round 2: P2 → P1  
P2: 接收{H(vᵢ)^k₁} → 计算Z = {H(vᵢ)^(k₁k₂)} (随机打乱)
    同时: W = {(wⱼ,tⱼ)} → {(H(wⱼ)^k₂, Enc(tⱼ))} (随机打乱)
    → 发送(Z, 加密对)给P1

Round 3: P1 → P2
P1: 计算H(wⱼ)^(k₁k₂)，检查是否∈Z (找交集)
    → 同态求和交集中的Enc(tⱼ) → 发送给P2

输出:
P2: 解密得到∑{tⱼ : wⱼ ∈ V∩W}
```

### 预备阶段

1. **DDH群生成**: 生成安全参数下的DDH群 (p, q, g)
2. **密钥生成**: P2 生成Paillier公私钥对 (pk, sk)，并将公钥 pk 发送给P1

### Round 1: P1 → P2

```
对于每个 vᵢ ∈ V:
1. 计算 H(vᵢ) → 映射到群元素
2. 计算 H(vᵢ)^k₁ mod p  (k₁是P1的随机私钥)
3. 随机打乱顺序后发送给P2
```

### Round 2: P2 → P1

P2 收到 {H(vᵢ)^k₁} 后执行两个并行操作：

**操作A: 计算Z集合**
```
对于收到的每个 H(vᵢ)^k₁:
1. 计算 (H(vᵢ)^k₁)^k₂ = H(vᵢ)^(k₁k₂)  (k₂是P2的随机私钥)
2. 收集所有结果到集合Z中
3. 随机打乱Z的顺序
```

**操作B: 加密自己的数据**
```
对于每个 (wⱼ, tⱼ) ∈ W:
1. 计算 H(wⱼ)^k₂
2. 计算 Enc(tⱼ) 使用Paillier加密
3. 形成对 (H(wⱼ)^k₂, Enc(tⱼ))
4. 随机打乱所有对的顺序
```

P2 将 Z 和加密对列表发送给P1。

### Round 3: P1 → P2

P1 执行私有集合交集计算：

```
1. 对每个收到的对 (H(wⱼ)^k₂, Enc(tⱼ)):
   - 计算 (H(wⱼ)^k₂)^k₁ = H(wⱼ)^(k₁k₂)

2. 找出交集:
   - 检查 H(wⱼ)^(k₁k₂) 是否在集合Z中
   - 如果在，说明存在某个vᵢ使得 H(vᵢ) = H(wⱼ)，即 vᵢ = wⱼ

3. 同态求和:
   - 对所有交集中的 Enc(tⱼ) 执行同态加法
   - 计算 ⊕{Enc(tⱼ) : wⱼ ∈ 交集} = Enc(∑tⱼ)

4. 重新随机化并发送结果给P2
```

### 输出阶段

P2 使用私钥解密收到的密文，得到交集元素数值的总和。

## 安全性分析

### 隐私保护

1. **P1的隐私**: 通过DDH假设的随机化，P2无法从 H(vᵢ)^k₁ 推断出原始标识符vᵢ
2. **P2的隐私**: P1只能学到交集的数值总和，无法得知具体的交集元素或非交集元素的信息
3. **交集隐私**: 双方都无法得知具体的交集元素，只有P2能得到交集大小的上界

### 密码学假设

- **DDH假设**: 保证群元素的随机化不可区分
- **Paillier安全性**: 保证加密数值的语义安全
- **半诚实模型**: 协议在半诚实敌手模型下是安全的

## 实现特点

### 技术亮点

1. **高效的群运算**: 使用安全素数构造的DDH群
2. **完整的同态加密**: 实现了Paillier的完整功能（加密、解密、同态加法、重随机化）
3. **随机化保护**: 在每个阶段都进行随机打乱以增强隐私保护
4. **模块化设计**: 清晰分离DDH群操作和Paillier操作

### 性能优化

- 使用高效的模幂运算
- 支持批量同态运算
- 内存友好的迭代器设计

## 安装与运行

### 环境要求

- Python 3.7+
- sympy库（用于生成安全素数）

### 安装依赖

```bash
pip install -r requirements.txt
```

或手动安装：
```bash
pip install sympy>=1.9
```

### 运行示例

```bash
python3 prog.py
```

示例输出：
```
Intersection identifiers: {b'userB', b'userC'}
Expected sum: 30
Decrypted sum: 30
```


### 技术优势

- ✅ **完全隐私保护**: 双方都无法获得对方的原始数据
- ✅ **精确计算**: 得到准确的数值统计结果  
- ✅ **可扩展性**: 支持大规模数据集处理
- ✅ **抗合谋**: 在半诚实模型下安全

## 参考文献

- Thomas Ristenpart, Peter H. Schacham, and Scott Yilek. ["Password checkup for Google users"](https://eprint.iacr.org/2019/723.pdf). *IACR Cryptology ePrint Archive*, Report 2019/723, 2019.
- Pascal Paillier. "Public-key cryptosystems based on composite degree residuosity classes." *EUROCRYPT*, 1999.

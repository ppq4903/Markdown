# Automated Mass Malware Factory: The Convergence of Piggybacking and Adversarial Example in Android Malicious Software Generation

自动化大规模恶意软件工厂：Android恶意软件生成中搭载攻击与对抗性示例的融合

† 华中科技大学 ‡ 香港理工大学

NDSS 2025

该研究提出一种**自动化批量生成 Android 对抗性寄生恶意软件**的方法，核心是将**寄生型恶意软件（Piggybacking）** 与**对抗样本技术**融合，通过 “恶意载体提取（Malicious Rider Extraction）、对抗扰动生成（Adversarial Perturbation Generation）、良性载体选择（Benign Carrier Selection）” 三大模块实现：先从现有良性 - 恶意 APP 对中提取 348 个符合功能要求的恶意载体（Rider），再通过 “热身阶段（训练替代模型）+ 微调阶段（目标模型反馈）” 生成仅对特定 Rider 有效的对抗扰动（借助 LLM 生成自然代码以隐藏痕迹），最后选择高兼容性、高流行度的良性载体（Carrier）；实验表明，该方法单线程日均可生成约**3760 个**恶意软件，对 DREBIN、MaMaDroid 等 6 个学术检测模型平均攻击成功率（ASR）达**88.3%**，对 Microsoft、NANO Antivirus 商业引擎 ASR 分别为**71%** 和**67%**，同时探讨了对抗重训练等潜在防御措施。

## 相关概念理解

**寄生型恶意软件**：

构成：恶意载体（Rider，实现恶意功能）+良性载体（Carrier，原始APP）+钩子（Hook，连接两者执行流）。

修改文件：

- META-INF：重签名（jarsigner 工具）

- Classes.dex：添加 / 修改 smali 代码（影响函数调用图）

- AndroidManifest.xml：新增恶意权限（如 WAKE_LOCK）、组件信息

- Res/lib：新增资源文件、原生库（C/C++）

**AMD对抗样本攻击**：

对抗样本是指**在原始输入数据中注入人类不可感知（或低感知）的微小扰动，使机器学习模型（尤其是深度学习模型）以高置信度输出错误结果**的特殊数据样本。

APK-specific：为单个APK生成扰动，需重复修改；APK-agnostic：生成通用扰动，适配多个APK。

## 研究背景和研究目标

- ML-based Android恶意软件检测（AMD）易受对抗样本攻击，但现有对抗技术忽视恶意软件生成过程
- 寄生型恶意软件现状：77%谷歌Play Top50免费应用被篡改，是批量传播恶意软件的主要方式

### 研究目标

批量生成逃避检测的对抗性寄生恶意软件，满足**通用性（扰动适配多种良性载体）**和**针对性（扰动仅对特定恶意载体有效以减少滥用）**

解决现有对抗技术 “与恶意功能耦合松散、难以批量应用” 的问题

## 核心方法

### 1、恶意载体提取

步骤：代码相似性分析（Androguard）→筛选符合R1-R3要求的Rider→模拟器验证功能→调试补全权限

**筛选依据**：1497 对 “良性 - 寄生恶意 APP”，通过三大要求筛选：

- R1：仅通过 1 个钩子函数（Hook）调用 Rider。
- R2：钩子函数位于载体的原始启动组件（确保 Rider 必执行）。
- R3：不删除载体的 smali / 权限 / 资源文件（支持自动化植入）。

**功能验证**：

- 步骤 1：用脚本筛选符合 R1-R3 的 Rider 候选。
- 步骤 2：植入最小测试载体，在 Android 模拟器运行验证功能。
- 步骤 3：调试失败样本（补全缺失权限 / 组件），重新验证。

结果：获取348个Rider，65个功能完全正确

### 2、对抗扰动生成

两阶段：热身阶段（训练4个替代模型预生成扰动）+微调阶段（基于目标模型二进制反馈优化）

优化：转化为max-min问题，平衡通用性与针对性

#### 代码生成：

用LLM（GPT-3.5-turbo）生成自然代码，结合Try-Catch Trap满足功能一致性。

要求：满足程序正常执行（R1）、功能一致性（R2）、自然性（R3）、灵活性（R4）

流程：

1. 拆分特征空间扰动为块（如 1 个权限 / 1 组 API 为 1 块）；
2. 构建模板 prompt（如 API 生成：“创建 Lcom/api/ae/num.smali，仅调用 API X”）；
3. 用 GPT-3.5-turbo 生成代码，结合 Try-Catch Trap 隐藏扰动；
4. 脚本辅助调试（补全寄存器声明、修复语法错误），直至重打包成功。

### 3、良性载体搭建

指标：Score(x_b) = Σ(-F_i(x_b + r + p))（综合检测逃避性能）

类别：优先选择GAME、PERSONALIZATION等高流行度类别




































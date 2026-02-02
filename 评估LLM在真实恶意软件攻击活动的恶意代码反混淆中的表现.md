# Assessing LLMs in malicious code deobfuscation of real-world malware campaigns

评估LLM在真实恶意软件攻击活动的恶意代码反混淆中的表现

本研究聚焦**大型语言模型（LLMs）** 在真实恶意软件反混淆中的应用，以**Emotet 恶意软件**的混淆 PowerShell 脚本为实验对象，测试了**GPT-4**、**Gemini Pro**、**Code Llama**和**Mixtral**四种主流 LLM 的反混淆能力。实验基于 2000 个 Emotet 脚本（含 2869 个唯一 URL、2512 个唯一域名），结果显示**GPT-4 表现最优**，URL 提取准确率达**69.56%**，域名提取准确率达**88.78%**；而本地模型（Code Llama、Mixtral）准确率仅为 22.13%、11.59% 且存在大量幻觉。研究指出，LLMs 虽未实现完美反混淆，但在自动化威胁情报管道中具有显著潜力，需通过微调优化，可辅助传统反混淆工具提升恶意软件分析效率。

## 背景

### Emotet 恶意软件详解

- **传播模式**：采用 “恶意软件即服务（MaaS）”，通过钓鱼邮件分发带 VBA 的 Office 文档（dropper），利用**LOLBAS 工具**（如 Regsvr32.exe、Winword.exe）绕过用户授权，后台下载执行恶意二进制文件。
- **混淆特征**：dropper 使用**Base64 编码的混淆 PowerShell 脚本**，含 5-8 个 URL（平均 6.6 个），指向被攻陷的 WordPress 域名；变量随机命名、含死代码，规避静态分析。
- **历史动态**：2021 年被 Europol 捣毁后复活，dropper 扩展至 Excel、OneNote 文件，持续推送新 campaign。
- **防御难点**
  - 混淆技术规避静态检测：传统杀毒软件的 “签名匹配” 对其变种无效，启发式规则也难以识别 “合法工具滥用” 的行为；
  - 动态适配快：攻击者会频繁更新混淆方式、C2 域名和传播载体（如从 Word 扩展到 OneNote），导致传统反混淆工具需手动补丁才能适配（文档 7）；
  - 幻觉风险：即使使用 AI 工具（如 LLMs）反混淆，本地模型（如 Code Llama、Mixtral）仍存在大量 “幻觉域名”（如 `admins.com`），可能导致误封合法网站（文档 6）。
  - 当前防御需结合 “多层次检测”：如邮件网关拦截钓鱼附件、终端监控 LOLBAS 异常调用、利用威胁情报（如 IOC 中的恶意域名 / URL）提前封禁，同时可辅助 LLMs（如 GPT-4，URL 提取准确率 69.56%、域名提取准确率 88.78%）提升反混淆效率（文档 6、7）。

### 恶意软件分析技术

| 分析类型 |                 核心方法                  |             局限性             |
| :------: | :---------------------------------------: | :----------------------------: |
| 静态分析 | 提取字节流、导入库、哈希值（ssdeep/TLSH） |   易被 Packers/Cryptors 规避   |
| 动态分析 |  沙箱 / 模拟器执行，记录网络 / 文件操作   | 无法覆盖所有代码路径，需资源多 |

- **规避技术**：Packers（压缩代码，含解压存根）、Cryptors（加密代码，含解密存根，支持多态 / 变形），部分含反调试 / 反虚拟化功能。

##### 

## 实验设置

### LLM 选择与参数配置

| LLM 类型 |        模型名称         |                关键参数                |  部署方式   |
| :------: | :---------------------: | :------------------------------------: | :---------: |
|  云模型  |   GPT-4（gpt-4-1106）   |                温度 = 0                | OpenAI API  |
|  云模型  |       Gemini Pro        |                温度 = 0                | Google API  |
| 本地模型 | Code Llama 34B Instruct | 温度 = 0，repeat_penalty=1.5，8 位量化 | NVIDIA A100 |
| 本地模型 |  Mixtral 8x7B Instruct  | 温度 = 0，repeat_penalty=1.5，8 位量化 | NVIDIA A100 |

- **参数目的**：温度 = 0 确保结果确定性、低幻觉；repeat_penalty=1.5 减少本地模型重复生成幻觉 URL。

### 提示工程

- **核心策略**：迭代优化提示，避免 LLM 生成 Python 代码（倾向 “任务分解” 而非直接反混淆）；明确要求处理**字符串拼接、Unicode 替换**，提取以 http/https 开头的 URL，输出 JSON 格式。
- **示例**：对 GPT-4 提示 “简化循环前代码、移除死代码、拼接字符串，返回最长字符串中的 URL”；对 Code Llama 采用特定 INST/SYS 格式约束输出。

### 数据集详情

- **规模**：2000 个随机 Emotet 混淆 PowerShell 脚本（约占其 campaign 的 5%），对应**2869 个唯一 URL**、**2512 个唯一域名**。
- **Ground Truth 获取**：通过 ViperMonkey 提取 Office 文档中的 VBA 代码→Base64 解码→PWSH（Linux 版 PowerShell）解析→威胁情报平台验证 URL / 域名正确性。

## 讨论：LLM 辅助威胁情报 pipeline 设计

传统反混淆工具的局限性：需针对特定混淆算法（如 Emotet 的 InvokeObfuscation）定制规则，当恶意软件更新混淆方式（如 Emotet 扩展 dropper 至 OneNote）时，工具需手动补丁，导致 IOC 提取延迟。

**流程**：恶意 Office 文档→沙箱 / 模拟器（提取混淆 PowerShell 载荷）→分发给**传统反混淆工具**和**LLM**→工具成功则输出 IOCs，失败则由 LLM 补充提取→LLM 额外生成代码功能总结 + MITRE ATT&CK 方法映射（如 T1566 “钓鱼”、T1105 “入口工具传输”）。

**优势**：弥补传统工具对新型混淆的适配延迟，提升 IOC 提取覆盖率，减少人工操作。






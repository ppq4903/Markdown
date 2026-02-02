# A survey on large language model (LLM) security and privacy:The Good, The Bad, and The Ugly

大型语言模型（LLM）的安全性与隐私性综述：光明面、阴暗面与丑陋面

该综述（发表于*High-Confidence Computing 4 (2024)*）由美国德雷塞尔大学团队撰写，通过梳理**281 篇 LLM 安全与隐私相关论文**，首次从 “The Good（正面应用）”“The Bad（恶意应用）”“The Ugly（LLM 漏洞与防御）” 三方面系统分析 LLM 与安全隐私的交集；其中，“The Good” 聚焦 LLM 对**代码安全（漏洞检测、代码修复等全生命周期支持）** 和**数据安全与隐私（完整性、机密性保护等）** 的提升，多数研究显示其性能远超传统方法；“The Bad” 指出 LLM 可被用于硬件 / OS / 软件 / 网络 / 用户级攻击，**用户级攻击（33 篇相关论文）最普遍**，因 LLM 类人推理能力；“The Ugly” 分析 LLM 的 AI 固有漏洞（数据投毒、训练数据提取等）与非 AI 固有漏洞（RCE、供应链漏洞等）及对应防御机制，同时发现**模型 / 参数提取攻击研究有限（多为理论）** 、安全指令调优需进一步探索；最终得出 LLM 对安全隐私的正面贡献多于负面的结论，为后续研究提供方向。
# CyberLLMInstruct: A Pseudo-Malicious Dataset Revealing Safety-Performance Trade-offs in Cyber Security LLM Fine-tuning

CyberLLMInstruct：一个伪恶意数据集揭示网络安全LLM微调中的安全性能权衡

表于 **AISec '25** 。英国肯特大学团队提出**CyberLLMInstruct**—— 一个包含**54,928 条伪恶意指令 - 响应对**的网络安全数据集，覆盖恶意软件分析、钓鱼模拟等任务，数据来源包括 CTF 挑战（27%）、学术论文（22%）等权威渠道；通过对**7 个开源 LLM**（如 Llama 3.1 8B、Mistral 7B）的评估发现，基于该数据集的微调虽能显著提升网络安全任务性能（在 CyberMetric 基准上最高达**92.50% 准确率**），但会严重削弱模型安全韧性（如 Llama 3.1 8B 针对提示注入的安全评分从**0.95 降至 0.15**），最终揭示网络安全 LLM 微调中的**安全 - 性能权衡**问题，强调需开发兼顾两者的微调方法。


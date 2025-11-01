---
typora-root-url: ./pictures
---

# RedCoder

## 一、研究背景

之前针对 Code LLM 的红队工作已经取得了重要进展，但它们主要关注单轮设置（Improta，2023 年；Cotroneo 等人，2024 年）。这些方法通常涉及制作不完整或具有微妙误导性的代码片段（Jenko 等人，2025 年；Pearce 等人，2025 年），或优化对抗性提示（Heibel 和 Lowd，2024 年；Wu 等人，2023 年）以引出易受攻击的输出。

这些方法：通常依赖于大量的人力——无论是在工程部分代码上下文中还是在手动指导提示优化过程中——使得它们难以扩展。此外，这些努力通常忽视了现实世界人工智能辅助编程的交互本质，而现实世界中的人工智能辅助编程通常会在多个回合中展开

对**可扩展、自动化**红队框架的需求

## 二、REDCODER红队框架

### 1、概览

一个针对 Code LLM 的**多轮对抗**代理

目标是系统地评估代码LLM在生成安全关键输出时的最坏情况行为，特别是表现出常见弱点枚举（CWE1；MITRE 2025）定义的漏洞的代码。

从**多代理博弈过程**开始，涉及：生成对抗性查询的**攻击者**、在多回合护栏下响应的**防御者**、检测漏洞归纳的**评估器**以及从不断发展的对话中提取可重用攻击策略的**策略分析师**。

攻击者和防御者进行**迭代的多轮对话**（根据实时响应动态调整），产生优化的原型对话，从而引发易受攻击的代码。 与此同时，策略分析师会比较失败和成功的尝试，以构建攻击策略库。

对原型对话进行微调，以作为 REDCODER 的支柱。一旦部署，代理就会使受害者模型2参与多轮攻击，从攻击策略库中检索相关策略，以随着时间的推移调整其提示。

在不同的 Code LLM 套件中进行了广泛的实验：REDCODER 大大优于现有的单轮（Liu 等人，2024；Zou 等人，2023）和多轮（Ren 等人，2024；Yang 等人，2024b）红队方法，实现了显着更高的漏洞诱导率。

### 2、详细框架

REDCODER 和受害者进行对话 C = {(q1, r1),(q2, r2), 。 。 。 ,(qk, rk)}，其中 qi 是代理在第 i 轮的话语，ri 是受害者模型的相应响应，k 是对话的最大长度。

在**多代理博弈过程（2.2）**中生成两个关键资源：
（1）成功诱发漏洞的原型对话集合；（2）由从攻击过程中提取的可重用对抗策略组成的策略库。

原型对话将用作训练数据，以微调作为 REDCODER 骨干的红队 LLM，使其能够生成适合上下文的多轮话语，从而逐步引导对话走向**漏洞归纳（2.3）**

### 2.2  多代理博弈

四组件：

- 攻击者代理：生成对抗性话语以引发脆弱的响应。
- 防御代理：在多匝护栏的保护下做出响应，模拟现实世界的安全约束。
- 评估代理：确定是否已成功诱导易受攻击的代码。
- 策略分析代理：从不断发展的对话中提取可重用的攻击策略。

以此自动探索针对 Code LLM 的攻击的搜索空间 并系统地构建一组不同的原型对话和可重用的策略库。

详细过程：

![image-20251023194033210](/image-20251017161840587.png)

1. 给定一个诱发漏洞的编码任务，攻击者和防御者进行多轮对话，其中攻击者试图从防御者那里引出易受攻击的代码。
2. 对话结束后，评估者审查完整的对话并确定任何响应是否包含安全漏洞。
3. 根据此反馈，攻击者会被提示反思结果并生成下一次对话尝试。
4. 迭代循环持续到完成预定数量的攻击尝试。所有被评估者判断为成功的对话都被保存为原型对话
5. 与此同时，策略师比较每一条任务的成功/失败的尝试，提取有意义的行为转变（被提炼的高级策略）存储在**策略库**（RAG机制）

- 攻击者的**历史感知提示机制**：将前一次尝试的完整对话 C 及其相应的检测结果合并到下一次攻击尝试的系统提示中。使得攻击者反思之前的结果并相应地调整其行为（调整措辞或避免无效策略）。如果成功，攻击者也将被引导改进其查询以提高隐蔽性或多样性。

- 防御者的**强力防守**：由**编码代理**（做出响应）和**护栏模型**（判断当前对话是否安全）组成。<img src="C:\Users\123\AppData\Roaming\Typora\typora-user-images\image-20251023200307406.png" alt="image-20251023200307406" style="zoom:82%;" />，采用最先进的护栏 ThinkGuard （一种**批判增强**的护栏模型，从高容量的 LLM 中提取推理知识，实现动态防御）

*以上的动态攻防模式确保攻击者不仅必须引出易受攻击的输出，而且还要在对话的每一步逃避主动安全过滤。*

- 评估者：漏洞检测和攻击成功评估。完成对话 C = {(q1, r1),(q2, r2), . 。 。 ,(qk, rk)} 后，从防御者的响应 {ri} 中提取所有代码片段，专注于检测与常见弱点枚举 (CWE) 分类法（MITRE，2025）相关的漏洞。使用Amazon CodeGuru6 作为评估器实现自动检测。

- 策略分析师：构建可重用策略库来指导未来的攻击。假设成功是由 Csucc 中引入的特定行为变化驱动的——纠正或改进之前失败的策略。我们将⟨Cfail，Csucc⟩ 指定为**过渡对话对**，它捕获了攻击迭代中的策略改进，然后让LLM比较两次对话并总结关键行为变化提取为摘要。   

  测试时检索模块：为了攻击阶段能根据**本地交互相似性**检索相关策略——键值存储：将成功的对话分割为单轮交互对 (qi , ri )。对于每一对，我们使用**文本嵌入模型计算嵌入并将其存储为检索键**。来自给定对话的所有 (qi , ri) 嵌入都**指向从该转换中提取的相应策略摘要**。

### 2.3 训练REDCODER（微调）

每个原型对话都被分解为输入-输出对，以进行**监督微调**。

输入由第 i−1 轮之前的对话历史记录组成，即 C = {(q1, r1),(q2, r2), 。 。 。 ,(qi−1, ri−1)}，输出是相应的下一个话语 qi 。

通过学习在不同的多轮上下文中生成 qi，REDCODER 获得了自适应地将对话引向脆弱性诱导响应的能力。

该训练过程**将成功原型对话中嵌入的策略知识提炼成独立的模型组件**。

与基于搜索的方法不同，生成的模型是**轻量级的、可推广的**，并且与测试时检索模块结合时能够进行**实时红队**。

### 2.4 部署REDCODER

REDCODER，即微调的红队LLM+RAG模块。

- 微调红队LLM与受害者 Code LLM 进行多轮对抗性对话，与受害者模型进行交互式对话。

- RAG机制从策略库中检索攻击策略——在多智能体博弈过程中提炼出的可重用策略的集合。

  具体来说，对于每个回合 i > 1，我们使用武器库构建期间使用的相同文本嵌入模型（第 2.2 节）来计算先前交互的嵌入 (qi−1, ri−1)。然后，REDCODER 根据余弦相似度检索其键与此嵌入最相似的策略。相应的策略摘要被注入到系统提示中，以指导智能体的下一代，使其能够根据之前成功的策略来调整其行为。

*这种检索增强的提示使代理能够动态地结合游戏过程中的相关战术知识，显着提高其绕过安全机制并实时诱导易受攻击的输出的能力。*

## 三、实验和结果

### 1、实验设置

#### 数据集

涵盖 43 个不同安全漏洞的 170 个编码任务的基准，涵盖了 CWE 分类法的代表性子集。

- 种子任务（43个）：直接请求易受攻击的代码生成来生成种子指令

- 增强任务：通过提示 GPT-4o 创建**更自然的任务**来执行逆向工程增强

#### Baselines

与自动红队方法进行比较

单轮攻击：AutoDAN，它使用**分层遗传算法**来优化对抗指令；
GCG，通过**结合贪婪和基于梯度的搜索技术**来构造对抗性后缀，这些后缀附加到提示中以引发有害输出。

- Xiaogeng Liu, Peiran Li, Edward Suh, Yevgeniy Vorobeychik, Zhuoqing Mao, Somesh Jha, Patrick McDaniel, Huan Sun, Bo Li, and Chaowei Xiao. 2025.**Autodan-turbo**: A lifelong agent for strategy selfexploration to jailbreak llms. ICLR.
- Andy Zou, Zifan Wang, Nicholas Carlini, Milad Nasr, J Zico Kolter, and Matt Fredrikson. 2023. Universal and transferable adversarial attacks on aligned language models. arXiv preprint arXiv:2307.15043.

多轮攻击：CoA-Feedback，一种**语义驱动**的多轮攻击框架，可根据上下文反馈自适应地修改查询；ActorAttack（Ren et al, 2024），它构建了**相关“参与者”的语义网络**，以探索多样化且有效的多轮攻击路径。

- Xikang Yang, Xuehai Tang, Songlin Hu, and Jizhong Han. 2024b. **Chain of attack**: a semantic-driven contextual multi-turn attacker for llm. arXiv preprint arXiv:2405.05610.
- Qibing Ren, Hao Li, Dongrui Liu, Zhanxu Xie, Xiaoya Lu, Yu Qiao, Lei Sha, Junchi Yan, Lizhuang Ma,
  and Jing Shao. 2024. Derail yourself: Multi-turn llm jailbreak attack through self-discovered clues. arXiv
  preprint arXiv:2410.10700.

#### 实验细节

对每个任务运行 20 次迭代优化，每次对话上限为 k = 5 轮。

我们使用 GPT-4o (OpenAI, 2024) 作为攻击者模型。

对于防御系统，我们采用 Llama3-8B-Instruct（Grattafiori 等人，2024）作为编码代理，与基于 ThinkGuard 框架（Wen 等人，2025）的护栏模型配对，并根据原型对话进行重新训练。

使用 Amazon CodeGuru 作为自动评估器。

在测试时，使用 multilingual-E5-large-instruct (Wang et al, 2024) 作为**嵌入模型**来编码对话轮次以进行动态策略检索。

游戏过程总共生成 2098 个原型对话。

主要的评估指标：**漏洞率**——至少一个响应 (ri) 包含标记有 CWE 漏洞的代码的对话比例。

### 2、主要结果

<img src="C:\Users\123\AppData\Roaming\Typora\typora-user-images\image-20251023210611562.png" alt="image-20251023210611562" style="zoom:80%;" />

表 1：代码LLM的漏洞率。与基线方法相比，REDCODER 在所有测试模型中始终实现显着更高的漏洞率（范围从 39.41% 到 65.29%），有效触发易受攻击的代码片段的生成。

1、REDCODER 在评估模型中始终优于所有基线，表现出强大的有效性和普遍性。

2、它在不同模型系列中的稳健性能表明 REDCODER 对架构和对齐差异具有弹性，即使在对齐良好的代码 LLM 中也能保持其诱导易受攻击代码的能力。

3、推理已被证明可以帮助模型抵抗对抗性指令，但是，将更多推理能力纳入受害者模型似乎并没有显着提高鲁棒性。例如，尽管是一个以推理为中心的模型，DeepSeek-R1Distill-Llama-8B 在 REDCODER 的攻击下仍然表现出 40.00% 的漏洞率。

4、不同的模型对引发漏洞的提示表现出不同程度的固有敏感性。例如，CodeGemma-7B 和 Qwen2.5-Coder-7B  即使在无攻击的情况下也显示出相对较高的漏洞率（分别为 23.52% 和 14.70%），表明默认防御较弱。

5、现有的红队基线在诱导易受攻击的代码方面效果有限，在某些情况下产生的漏洞率低于无攻击设置。这凸显了它们的优化目标与代码漏洞领域的需求之间根本不匹配。

### 3、不同检索策略的影响

在两个 7B 规模的模型 CodeGemma 和 CodeLlama 上进行实验，

比较三种 RAG 配置： 

(1) Transition + Multi-Turn Retrieve8：在对话的每个回合，代理检索从 Transitioned Conversation Pairs 得出的策略摘要；

 (2) Success-Only + Multi-Turn Retrieve：每轮仍进行检索，但仅从成功的攻击会话中得出策略摘要，而不考虑失败的示例；

 (3) Transition+Single-Turn Retrieve：代理在第一轮之后从转换对中检索单个策略摘要，并在对话的其余部分重用相同的策略。

<img src="C:\Users\123\AppData\Roaming\Typora\typora-user-images\image-20251023212801216.png" alt="image-20251023212801216" style="zoom:80%;" />，结果表明，支持使用基于故障感知摘要的自适应多轮检索作为面向代码的红队最稳健的设计。

### 护栏代理的影响

在 CodeLlama-7B、CodeGemma-7B和 Qwen-Coder-7B上进行了两种护栏配置的测试

single-turn：护栏检查每个单独的交互

multi-turn：护栏扫描直到第 i 回合的完整对话历史记录，即 C = {(q1, r1),(q2, r2), 。 。 。 ,(qi , ri)}。

<img src="C:\Users\123\AppData\Roaming\Typora\typora-user-images\image-20251023212618654.png" alt="image-20251023212618654" style="zoom:80%;" />，结果发现：

（1）单匝护栏的影响可以忽略不计：无法有效检测漏洞，攻击成功率几乎没有变化。

（2）多匝护栏可提供部分缓解，降低所有模型的漏洞率。

*多轮攻击很少在任何单一话语中产生明显的恶意内容，但组合上下文可能会导致安全漏洞*

## 四、相关工作

### 对LLM的攻击：

训练时攻击：(1) 数据中毒，它操纵训练数据集以引发不安全的编码行为，例如忽略安全检查或滥用加密函数（Improta，2023；Cotroneo 等人，2024）； (2) 后门攻击，将隐藏的触发器植入模型中，在遇到特定输入时引发恶意输出（Huang 等人，2023 年；Li 等人，2023 年；Aghakhani 等人，2024 年）。

测试时攻击：通过提示操作来针对已部署的模型。早期工作使用对抗性扰动来误导模型对代码安全性进行错误分类，从而破坏了人工智能辅助编码工具的可靠性；最近的工作重点是代码生成，使用误导性的完成提示或优化指令来诱发漏洞。

### Automated Red-teaming：

Single-turn攻击：

- GCG——优化令牌插入以生成攻击后缀；
- AutoDAN——使用遗传算法来演化流畅的提示，从而规避安全过滤器和基于困惑的防御。

Multi-turn攻击：

- CoA（Yang 等人，2024b）构建了随模型响应而演变的自适应攻击链；
- ActorAttack（Ren 等人，2024）对此进行了扩展，围绕有害目标构建语义网络并动态优化查询，从而实现多样化且有效的攻击路径。

## 五、局限性

1、使用 Amazon CodeGuru 作为主要评估工具是一个务实但不完美的选择。尽管它提供了自动化、可扩展的漏洞检测，但它可能会错过某些安全问题，并且不能涵盖所有 CWE 漏洞。

2、研究侧重于漏洞的代表性子集，并未涵盖全部软件安全风险。使用 43 个常见弱点枚举 (CWE) 类型作为目标来开发和评估 REDCODER。虽然这些 CWE 涵盖了各种安全问题，并为自动化红队提供了有意义的覆盖范围，但它们并没有捕获代码生成中所有可能的故障模式。

3、未来工作可以扩大这些范围：更广泛的漏洞类别、不安全的编码模式或特定领域的风险。









## 四、

















































## 相关文献（红队相关工作）

1、Hammond Pearce, Baleegh Ahmad, Benjamin Tan,Brendan Dolan-Gavitt, and Ramesh Karri. 2025.
Asleep at the keyboard? assessing the security of github copilot’s code contributions. Communications
of the ACM, 68(2):96–105.——精心构建的代码完成提示

2、Cristina Improta. 2023. Poisoning programs by unrepairing code: Security concerns of ai-generated code. In 2023 IEEE 34th International Symposium on Software Reliability Engineering Workshops (ISSREW), pages 128–131. IEEE.——单论设置

3、Domenico Cotroneo, Cristina Improta, Pietro Liguori, and Roberto Natella. 2024. Vulnerabilities in ai code generators: Exploring targeted data poisoning attacks. In Proceedings of the 32nd IEEE/ACM International Conference on Program Comprehension, pages 280–292.——单论设置

4、John Heibel and Daniel Lowd. 2024. Mapping your model: Assessing the impact of adversarial attacks
on llm-based programming assistants. arXiv preprint arXiv:2407.11072.——优化对抗性提示

5、








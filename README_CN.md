# UsingBYOVD

[EN](./ReadMe.md) | 中文

![image](./pics/Logo.png)


UsingBYOVD 是一个基于 **BYOVD（Bring Your Own Vulnerable Driver，自带脆弱驱动）** 技术实现的 Windows 内核级安全研究与审计工具。通过利用已知合法驱动程序的内核漏洞，该工具可以绕过 Windows 系统的应用层防护与内核级限制，实现进程保护修改、权限提升、强杀防病毒软件（AV/EDR）以及内核驱动映射等高级操作。

> [!WARNING]
> **免责声明：** 本项目仅供网络安全研究、合规性渗透测试及漏洞验证使用。请勿将其用于任何非法用途。由于传播、利用本项目提供的功能而造成的任何直接或间接后果及损失，均由使用者本人承担。

---

## 🚀 核心功能

* **PPL 保护操控**：支持为指定进程动态添加或移除 PPL（Protected Process Light）保护，对抗高级 EDR 的内存注入与结束进程行为。
* **内核级权限提升**：直接在内核层级篡改进程 Token，将指定 PID 的进程权限提升至 `NT AUTHORITY\SYSTEM`。
* **强制结束进程 (EDR/AV Killer)**：绕过应用层常规 API 限制，利用内核能力强杀受保护的防病毒软件进程或指定 PID 进程。
* **内核驱动映射**：支持在启用驱动签名强制（DSE）的系统上，利用漏洞驱动将未签名的自定义驱动程序映射到内核空间。
* **凭据转储 (LSASS Dump)**：绕过常规读取限制，对 `lsass.exe` 进程进行内存转储，用于后续的凭据分析。

---

## 🛠 参数说明

程序通过命令行解析参数，各功能支持简写及大小写模糊匹配，具体参数映射如下：

| 长参数 | 短参数 | 接受值 | 功能描述 |
| :--- | :--- | :--- | :--- |
| `--ppl` / `--PPL` | - | 无 | 激活 PPL 操作模式，需配合 `-add` 或 `-rve` 使用 |
| `-add` / `-ADD` | `-a` / `-A` | `<PID>` | **添加**操作。若处于 PPL 模式则为指定 PID 开启 PPL 保护 |
| `-rve` / `-RVE` | `-r` / `-R` | `<PID>` | **移除**操作。若处于 PPL 模式则为指定 PID 解除 PPL 保护 |
| `--PriEsc` / `--PS` | - | `<PID>` | 对指定的 `<PID>` 进程进行**权限提升**（Token 窃取/替换） |
| `--KillProcess` / `--k` / `--K` | `-k` / `-K` | `<PID>` | 强行**结束（Kill）**指定 `<PID>` 的进程 |
| `--ka` / `--KA` | - | 无 | **自动强杀**系统中所有已知的反病毒软件/安全防护进程（AV/EDR） |
| `--map` / `--m` / `--M` | `-m` / `-M` | `<驱动路径>` | **映射驱动**。利用漏洞驱动加载指定路径下的未签名驱动 |
| `--dmp` | - | 无 | **转储 LSASS**。导出 `lsass.exe` 进程的内存文件 |
| `--help` | `-h` | 无 | 显示彩色帮助信息并退出程序 |

---

## 💡 使用示例

### 1. PPL 保护管理
* **为指定进程添加 PPL 保护**（防止被其他低权限或同权限进程结束）：
  ```bash
  UsingBYOVD.exe --ppl -add 1234
  ```
* **移除指定进程的 PPL 保护**（通常用于解除安全软件的自我保护）：
  ```bash
  UsingBYOVD.exe --ppl -rve 5678
  ```

### 2. 权限提升
* **将指定 PID 提升至 SYSTEM 权限**：
  ```bash
  UsingBYOVD.exe --PriEsc 4321

  UsingBYOVD.exe --PriEsc（提升自身进程）
  ```

### 3. 强杀进程与安全软件
* **强杀特定 PID 的顽固进程**：
  ```bash
  UsingBYOVD.exe --KillProcess 9999
  ```
* **一键清除全线已知 AV/EDR 进程**：
  ```bash
  UsingBYOVD.exe --ka
  ```

### 4. 驱动映射与内核加载
* **无视 DSE 签名强制，加载自定义驱动**：
  ```bash
  UsingBYOVD.exe --map C:\path\to\your_unsigned_driver.sys

  UsingBYOVD.exe --map(加载示例驱动)
  ```

### 5. 凭据导出
* **转储 LSASS 内存以获取凭据**：
  ```bash
  UsingBYOVD.exe --dmp
  ```

---

## ⚙️ 编译与依赖

1. **环境要求**：支持 MSVC 编译器，建议使用 Visual Studio 2019 进行编译。
2. **注意事项**：
   * 本项目运行需要**管理员权限**（以便加载最初的漏洞驱动）。
   * 使用前请确保对应的漏洞驱动（Vulnerable Driver）与可执行文件处于同一目录下，或已正确集成在资源文件中。

## 参考项目
> SysWhispers4 : [SysWhispers4](https://github.com/JoasASantos/SysWhispers4)  
> superfetch : [PPLShade](https://github.com/redteamfortress/PPLShade/blob/main/PPLShade/superfetch.h)  


## BYOVD

**Killer**


| DeviceName | SHA256 | IOCTL CODE | Resources |
| :---: | :---: | :---: | :--- |
| ardrv| 07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541 | 0x2420031 |https://github.com/redteamfortress/CVE-2026-36425 https://github.com/magicsword-io/LOLDrivers/issues/374|
| BootRepair| 5ab36c116767eaae53a466fbc2dae7cfd608ed77721f65e83312037fbd57c946 | 0x222014 |https://medium.com/@jehadbudagga/phantom-killer-reverse-engineering-and-weaponizing-a-lenovo-driver-to-terminate-edr-processes-9191cd06374f  https://github.com/redteamfortress/PhantomKiller|
| ProcessCtr| d64eeb940daffdc8327fb18b160c20e539088cf8407813655f59efa9fdf0022e | 0x89DB202C |https://github.com/The-Sword-of-Constantine/UsingBYOVD/blob/master/BYOVD/ProcessCtr.cpp https://github.com/KOSEC-LLC/BYOVD-Research/tree/main/EsafeNet|
| GGProtect64| 0aa69aee93c6be9bc82680a7df99c114591038ae02e6666fc6e42acb09643111 | 0x223C04 |https://github.com/magicsword-io/LOLDrivers/issues/325 https://github.com/magicsword-io/LOLDrivers/issues/368 https://github.com/KeServiceDescriptorTable/vulnerable-drivers https://github.com/Haider303/GGProtect-exploit https://medium.com/@haider303mustafa/bypassing-weak-driver-authentication-to-kill-ppl-protected-processes-ggprotect64-sys-analysis-d8f44c5837b4|
| HWAuidoOs2Ec.sys| 90d2e9e994ed8e964845a26dce741ad43b29ff54cf5faa67271d62d4e24acbc8 | 0x2248DC |https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework https://github.com/magicsword-io/LOLDrivers/issues/325 |
|DCRCVDrv.sys|87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff|0x2205C0u|https://github.com/magicsword-io/LOLDrivers/issues/403  https://x.com/YungBinary/status/2085255978367569939?s=20|  
|MonProcessEX.sys  MonProcess.sys|72d0b5615b996cbb01b1ca139e627079094f734da48a0435ffd8480a25d0a258  8a8652604f7789a6259ae05266652580b18729e1f1c05612b9d338eb8379ecee|0x22400Cu| https://github.com/magicsword-io/LOLDrivers/issues/384 |  



## ⚠️ 声明

* **代码许可**：本项目基于 **AGPL-3.0** 协议开源。任何衍生项目（包含通过网络提供服务的在线工具或云端平台）必须保持开源，并完整保留原作者的署名及版权声明。
* **拒绝洗稿与私自备份**：未经作者（The-Sword-of-Constantine | Element2023H）书面授权，**严禁任何微信公众号、自媒体、个人博客或第三方平台对本项目文档、命令矩阵及技术细节进行不署名搬运、洗稿或二次打包备份**。任何合规的引用或推荐，必须在文章/项目显著位置（头部）加粗标注本项目 GitHub 唯一开源链接。


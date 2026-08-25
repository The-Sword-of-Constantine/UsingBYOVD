# UsingBYOVD

EN | [中文](./README_CN.md)

![image](./pics/Logo.png)

UsingBYOVD is a Windows kernel-level security research and post-exploitation tool utilizing the **BYOVD (Bring Your Own Vulnerable Driver)** technique. By leveraging known vulnerabilities within legitimately signed third-party drivers, this tool bypasses Windows user-mode and kernel-mode protections (such as DSE and EDR hooks) to perform advanced operations including PPL manipulation, token-stealing privilege escalation, kernel-level process termination, and unsigned driver mapping.

> [!WARNING]
> **Disclaimer:** This project is created strictly for educational purposes, authorized security auditing, and malware research. Do not use this tool for malicious activities. The author assumes no liability for any damage, data loss, or legal consequences caused by misusing this software.

---

## 🚀 Key Features

*   **PPL Protection Control**: Dynamically injects or strips Protected Process Light (PPL) attributes into/from active processes, rendering them immune to or vulnerable to user-mode tampering.
*   **Kernel Token Manipulation**: Directly modifies process tokens in kernel space to elevate any process to `NT AUTHORITY\SYSTEM`.
*   **EDR/AV Killer (Kernel-Level)**: Bypasses standard user-mode API limitations and EDR self-protection hooks by terminating security agents straight from the kernel layer.
*   **Unsigned Driver Mapping**: Exploits the vulnerable driver to map arbitrary, unsigned custom `.sys` files into the kernel space without triggering Driver Signature Enforcement (DSE).
*   **Credential Dumping**: Bypasses credential guards and access restrictions to create memory dumps of `lsass.exe` for offline credential analysis.

---

## 🛠 Command-Line Interface (CLI) Reference

The tool parses parameters case-sensitively or case-insensitively based on the specific flags implemented in the C++ source. Below is the precise parameter matrix:

| Long Flag | Short Flags / Aliases | Argument | Description |
| :--- | :--- | :--- | :--- |
| `--ppl`, `--PPL` | *None* | *None* | Enables PPL configuration mode. Must be paired with `-add` or `-rve`. |
| `-add`, `-ADD` | `-a`, `-A` | `<PID>` | **Add action**. Configures target PID for PPL protection if `--ppl` mode is active. |
| `-rve`, `-RVE` | `-r`, `-R` | `<PID>` | **Remove action**. Strips PPL protection from target PID if `--ppl` mode is active. |
| `--PriEsc`, `--PS` | *None* | `<PID>` | **Privilege Escalation**. Steals the SYSTEM token and applies it to the target PID. |
| `--KillProcess` | `--k`, `--K`, `-k`, `-K` | `<PID>` | **Force Kill**. Forcefully terminates the process matching the target PID from kernel space. |
| `--ka`, `--KA` | *None* | *None* | **Kill All AVs**. Automatically enumerates and terminates all known Antivirus/EDR processes. |
| `--map` | `--m`, `--M`, `-m`, `-M` | `<Path>` | **Driver Mapper**. Manually maps an unsigned driver file path into kernel space. |
| `--dmp` | *None* | *None* | **LSASS Dump**. Generates a raw memory dump file of the `lsass.exe` process. |
| `--help` | `-h` | *None* | Displays the built-in pink-colored help menu and terminates execution. |

---

## 💡 Usage Examples

### 1. PPL Protection Management

*   **Apply PPL Protection to a custom process** (Prevents user-mode EDR/AV from terminating your agent):
    ```cmd
    UsingBYOVD.exe --ppl -add 1234
    ```
*   **Remove PPL Protection from a target process** (Exposes an EDR/AV process for manipulation):
    ```cmd
    UsingBYOVD.exe --ppl -rve 5678
    ```

### 2. Privilege Escalation

*   **Elevate a specific process (e.g., cmd.exe) to SYSTEM**:
    ```cmd
    UsingBYOVD.exe --PriEsc 4321
    ```

### 3. Evading Security Software (AV/EDR Kill)

*   **Force-terminate a specific protected security process**:
    ```cmd
    UsingBYOVD.exe --KillProcess 9999
    ```
*   **One-click termination of all known AV/EDR processes running on the machine**:
    ```cmd
    UsingBYOVD.exe --ka
    ```

### 4. Kernel Driver Mapping

*   **Bypass DSE and load an unsigned custom kernel driver**:
    ```cmd
    UsingBYOVD.exe --map C:\Windows\Temp\my_unsigned_driver.sys
    ```

### 5. LSASS Memory Dumping

*   **Dump LSASS memory safely to disk**:
    ```cmd
    UsingBYOVD.exe --dmp
    ```

---


## ⚙️ Requirements & Compilation

1.  **Prerequisites**:
    *   **Privilege Requirements**: The executable must be run from an **Elevated Command Prompt (Administrator)**. The tool utilizes the Native API `NtLoadDriver` to map the driver, which strictly requires the **`SeLoadDriverPrivilege`** to be enabled in the process token.
    *   **Registry Configuration**: Ensure your execution context has sufficient integrity to write temporary keys under `HKLM\System\CurrentControlSet\Services` for `NtLoadDriver` to reference, or ensure the driver path is properly staged.
    *   **Driver Placement**: The vulnerable companion driver (`.sys`) must be present in the identical working directory as the executable, unless you have embedded the raw binary into the PE resource section (`.rc`) for runtime extraction.

2.  **Compilation**:
    *   Open the solution in **Visual Studio 2019**.
    *   Set the build configuration to **Release | Debug** and architecture to **x64**.
    *   Ensure the Windows SDK is properly linked. Compile the project.




## Syscall
使用了[SysWhispers4](https://github.com/JoasASantos/SysWhispers4)加入到了本项目

Special thanks to the author of [SysWhispers4](https://github.com/JoasASantos/SysWhispers4) for sharing this project.

## Superfetch
使用了[redteamfortress/PPLShade](https://github.com/redteamfortress/PPLShade) 项目中的superfetch

Utilizes the Superfetch implementation from [redteamfortress/PPLShade](https://github.com/redteamfortress/PPLShade) project.


## kdmapper
参考了[kdmapper](https://github.com/TheCruZ/kdmapper) 手动映射无签名驱动
Special thanks to the author of [kdmapper](https://github.com/TheCruZ/kdmapper) for sharing this project.

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


## ⚠️ Notice & License

* **Code License**: This project is licensed under **AGPL-3.0**. Any derivative works (including software modified to run as a network service or cloud platform) must remain open-source under the same license and preserve the original author's attribution and copyright notice.
* **Anti-Plagiarism**: Unauthorized copying, cross-posting, archiving, or publishing of this project's documentation on third-party platforms (e.g., media accounts, personal blogs) without explicit written permission is strictly prohibited. For any authorized references, proper attribution and a prominent link back to this original repository are mandatory.


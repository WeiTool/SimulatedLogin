# 云南财经大学校园网模拟登录工具

本项目基于 [CSDN博主huxiaofan1223文章](https://blog.csdn.net/qq_41797946/article/details/89417722) 和 [zu1k的srun开源项目](https://github.com/zu1k/srun) 实现，提供 **Java** 和 **Python** 双版本，支持云南财经大学校园网的自动化认证登录通过脚本实现一键登录。

---

## 功能特性
- **多语言支持**：提供 Java（JDK 24 + Gradle 8.14）和 Python（3.13.3）双版本实现。
- **自动化登录**：捕获校园网 Web 认证请求，模拟表单提交，支持开机自启动（Windows 计划任务）。
- **轻量级配置**：通过配置文件管理账号信息，避免代码硬编码敏感数据。
---

## 环境要求
### Java 版本
- JDK 8+
- Gradle 8.14
- 依赖库：com.google.code.gson:gson:2.8.9

### Python 版本
- Python 3.13.3
- 依赖库：`requests`（需 `pip install requests`）

---

## 快速开始
### 1. 克隆项目
```bash
git clone https://github.com/your-repo/yuncai-auth.git
```

### 2. 配置账号信息
- **Java**
- **Python**<br>
Java在上面的main方法中
python在下面的运行代码中

### 3. 运行脚本
- **Java**：
用idea打开后运行Main.java
- **Python**：
用pycharm打开后运行Main.py
---

## 注意事项
1. **验证码**：当前仅支持无验证码的 Web 认证系统。
2. **网络环境**：需确保设备已连接校园网且能访问认证页面。
3. **更新维护**：若校园网认证接口变更，需重新捕获请求参数并调整代码。

---

## 开源协议
本项目基于 GPL-3.0 协议开源，部分代码参考自 [srun](https://github.com/zu1k/srun) 的实现思路。

> 更多技术细节请参考：[CSDN原理解析](https://blog.csdn.net/qq_41797946/article/details/89417722) | [GitHub项目文档](https://github.com/zu1k/srun)
``` 
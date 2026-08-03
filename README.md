# ChangeGuard

面向 AI 改码场景的变更追踪与密钥扫描工具。

## 能做什么 / What it does
- 快照并对比新增、删除、修改文件
- 检测 `sk-`、RSA 私钥、PASSWORD 等敏感内容
- 标记 `.env` 与配置变更风险

## 快速使用 / Quick Start
```bash
python3 changeguard.py snapshot
python3 changeguard.py check
```

## 示例输出 / Example Output
```text
🔴 疑似密钥/密码泄露: .env
```

## 技术栈 / Tech
- Python 3.9+，标准库

## 适用场景 / Use Cases
- AI 改码复核、提交前安全检查

## 许可证 / License
MIT

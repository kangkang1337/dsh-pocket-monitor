# 本机推送辅助（`npm run push` 会用到）

这个目录里的东西**只服务于「在本机把代码推回 GitHub」**这件事，和 DSH Pocket Monitor 的运行完全无关。它存在的原因是这台机器的网络环境比较特殊：

| 现象 | 原因 |
| --- | --- |
| HTTPS 推 GitHub 报 `self-signed certificate in certificate chain` / `SEC_E_NO_CREDENTIALS` | 网络侧网关对 `github.com` 的 HTTPS 做了中间人（实测签发的证书链是 `Scholar Root CA v1` / `O=Scholar Verify`），git 自带的 CA 清单不认它 |
| SSH 的 22 端口连不上 | 网络封锁了 22 端口（`Test-NetConnection github.com -Port 22` 为 False） |
| 直接配 `core.sshCommand` 带参数会失败 | git 只要发现 sshCommand 带参数就经 `sh.exe` 启动，而本机的受限环境不允许创建信号管道（`couldn't create signal pipe, Win32 error 5`） |

解决办法就是这里的 `ssh-wrapper.cmd`：把「走 443 + 指定 known_hosts」藏进一个**无参数**的脚本，让 git 用 `GIT_SSH` 直接调它。

## 用法

```powershell
# 首次：生成 known_hosts（把 GitHub 的主机密钥记到本目录，避免交互卡住）
ssh -o UserKnownHostsFile=".\.ssh-local\known_hosts" -o StrictHostKeyChecking=accept-new -T git@github.com

# 之后每次推送
npm run push
```

`npm run push` 等价于：

```powershell
$env:GIT_SSH = "$PWD\.ssh-local\ssh-wrapper.cmd"
git push
```

## 说明

- `known_hosts` **不入库**（见 `.gitignore`），每台机器自己生成一次。
- 如果你的网络不需要这些绕行（例如换了网络、代理正常、GitHub SSH 22 端口可用），可以直接删掉这个目录，并：
  ```powershell
  git remote set-url origin https://github.com/kangkang1337/dsh-pocket-monitor.git
  ```
- 这里**没有**关闭任何 TLS 校验，也**没有**往系统证书库安装任何证书。

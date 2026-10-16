# DSH 接口勘查结论（阶段一）

> 勘查对象：本机 Windows 11 上实际安装并运行的 DeepSeek Harness。
> 勘查方式：直接读取已安装的 DSH 包源码/类型定义 + 对运行中的服务发真实请求 + 解码真实会话日志。
> 结论只包含**实测到的事实**；推断部分明确标注为「推断」。

## 0. 环境事实

| 项 | 实测值 | 来源 |
| --- | --- | --- |
| DSH CLI 版本 | `0.2.0-rc.2` | `dsh --version` |
| CLI 安装位置 | `%APPDATA%\npm-global\node_modules\@deepseek-ai\dsh` | `package.json` |
| DSH Home | `%USERPROFILE%\.dsh` | `dsh-home-paths` 约定 |
| 会话日志根 | `%USERPROFILE%\.dsh\sessions` | 实测目录存在 |
| Web profile 目录 | `%USERPROFILE%\.dsh\profiles\web` | 实测 |
| 运行中的 `dsh web` | `127.0.0.1:3080`（**仅 loopback**，PID 6944） | `netstat -ano` |
| 运行中的其他插件服务 | `0.0.0.0:3081`（同 PID，第三方 `dsh-pocket` 插件自带代理） | `netstat -ano` |
| Node | `v22.21.0`（内置 `node:zlib` Zstd API） | `node -v` |

会话日志实测样例（路径中的用户名与项目名已替换为占位符）：

```
%USERPROFILE%\.dsh\sessions\--C-Users-<用户名>-Desktop-program-personal-<项目名>--\
  <会话 UUID>\session.v4.jsonl.zstd
```

## 1. DSH Web 的认证机制（实测）

- `GET http://127.0.0.1:3080/` 返回 **401**；`/api`、`/api/health`、`/api/sessions` 一律 **401**；`/healthz`、`/ws` 是 **404**（未注册路由）。
- Host 头改成 `localhost:3080` 或伪造域名，仍 **401/403**。
- 依据 `@deepseek-ai/dsh-client-connection`（README.zh.md 与 `lib/index.js`）实测源码：
  - **每个 DSH Web 进程生成一个随机启动令牌（launch token）**，`dsh web` 启动时打印并打开 `http://<authority>/?token=<launchToken>`。
  - 只有 `GET /` 且带**唯一且匹配**的 `?token=` 时，才 `303` 换一个绑定 authority 的签名 cookie（`HttpOnly`、`SameSite=Strict`、`Path=/`，默认 30 天有效）。之后 `/api` 与 WebSocket 才放行。
  - 除根路径换 cookie 外，HTTP 载体**不接受** query token，也**不接受 `Authorization` 头**。
  - 所有请求先过 `isTrustedApiRequest`：`Host` 必须是 loopback 或 `trustedHosts` 条目，带 `Origin` 时必须等于该 Host，`sec-fetch-site: cross-site` 一律拒绝（403）。未认证返回 401。
  - cookie 签名密钥持久化在 `$DSH_HOME/.credentials.yaml` 的 `client-connection/browser-session` 记录里。
  - `dsh web --host 0.0.0.0` **被官方显式拒绝**（`startup.js` 里直接 `program.error`），理由是会把远程代码执行能力暴露到网络。
- 因此：**DSH Web 的 `/api` RPC 通道是「操作者级」的通用控制面**（能开会话、发消息、跑命令）。本项目**不使用**它，也**不读取 `.credentials.yaml` 伪造 cookie**（那属于绕过 DSH 权限检查）。

## 2. 审批机制（实测源码）

`@deepseek-ai/dsh-user-approval`（`lib/index.js` 第 128–144 行）实测：

```js
async request(req) {
  const session = req.agent.session;
  if (!hasOpenTurn(session)) throw new Error("approval.request() outside an open turn: ...");
  const id = ApprovalRequestId(randomUUID());
  session.append("approval/asked", { id, toolName, ...(callId && { callId }), ...(reason && { reason }) });
  const outcome = await this.decide(req, session);      // ← 决定来自进程内 waterfall
  session.append("approval/decided", { id, outcome });
  return outcome;
}
```

- 请求派发走 Cordis 的 **`approval/request` waterfall**（`ctx.waterfall(scopeTarget(agent), "approval/request", req, () => "unavailable")`）。应答者是**同一个 DSH 进程内**注册的监听器。
- 结果词表是封闭的：`allowed-once` | `rejected` | `cancelled` | `unavailable`。策略为 `never` 时在服务内部直接拒绝，不派发。
- Web GUI 之所以能在浏览器上点审批：`dsh-api-remotes` 把 `approval/request` 声明为 **waterfall 类型的转发事件**（`lib/index.js` 第 23 行、`lib/types/remote-events.js` 第 14 行），客户端插件 `@deepseek-ai/dsh-client-ui-approval` 通过 `ctx.remote.$on("approval/request", (request, next) => ...)` 作答（`lib/client.js` 第 355 行）。**这条通道本身要求操作者级浏览器会话**（见第 1 节）。
- 现有第三方 `dsh-pocket` 插件能远程审批，是因为它是**进程内插件**：它的 `lib/index.js` 第 324–333 行用 `ctx.connection.authenticatedUrl(...)` 从**自己的进程内存**里取 launch token，再把浏览器流量代理到 3080。

**结论（很重要）**：
- ✅ **「查看待审批」可以真实实现**：`approval/asked` 与 `approval/decided` 会**成对持久化到会话日志**，所以「有 `approval/asked` 而没有同 id 的 `approval/decided`」= 当前待审批。
- ❌ **「由外部进程执行审批」在 0.2.0-rc.2 上不可实现**：决定必须由 DSH 进程内的应答者给出；会话日志是仅追加的持久化产物，**没有面向外部进程的审批回写通道**。写日志不会影响正在运行的 DSH 进程状态（`decide()` 等待的是内存里的 Promise）。
- 因此本项目：审批的**权限校验、请求 ID 校验、状态校验、幂等性**全部真实实现并有测试覆盖；**只有「下发到 DSH」这一步如实返回「当前 DSH 版本不提供外部审批通道」**，绝不模拟批准成功，也不用通用 RPC 代偿。

## 3. 可用的外部只读数据源：会话日志

这是本项目**唯一**使用的 DSH 数据源（只读，不写、不改、不删）。

### 3.1 磁盘布局

依据 `@deepseek-ai/dsh-session-persistence-jsonl`（README.zh.md + `lib/index.js`）：

```
<sessionsRoot>/
  --<projectKey(cwd)>--/            # 可读的项目目录（cwd 未记录时为 _no-cwd）
    <encoded-session-id>/           # 会话自有目录
      session.v4.jsonl.zstd         # 当前格式（v4）压缩代际
      session.vN.jsonl.zstd         # 历史代际（本项目只读最高代际）
```

`projectKey()` 算法（`lib/index.js` 第 875–894 行，已逐行核对）：

- `/`、`\`、`:` → 折叠成一个 `-`（连续分隔符只算一个）；
- `[A-Za-z0-9._-]` 原样保留；
- 其他字符 → `~` + 4 位大写十六进制码位；
- 去掉前导 `-`，取前 251 字符；整体包成 `--<key>--`（空则为 `--root--`）。

本项目**不做反向解码猜测**：改为「扫描 `sessions/**` 下所有日志的 header，用 header 里的真实 `cwd` 匹配工作目录」，先精确计算 key 再扫描兜底。

### 3.2 物理编码（实测解码成功）

- 文件是**多个独立 Zstandard 帧的顺序拼接**：第 1 帧 = header 行，之后**每个持久化 append 批次 1 帧**，帧带校验和。
- 每帧解压后是若干行 UTF-8 JSONL（一行一个事件）。
- 帧边界必须靠**结构扫描**确定（`zstdDecompressSync` 对截断帧会静默返回部分结果，不能靠 try/catch 判断完整性）。官方扫描算法在本项目 `backend/src/adapters/dsh/session/zstd-frames.ts` 中**按源码 1:1 复刻**（`lib/index.js` 第 1300–1363 行）。
- 崩溃残留的「撕裂尾帧」只贡献能完整解出的记录；本项目按「保留最后一个完整帧的字节界」处理，不修改原文件。
- 已实测：`9c0764e8-...` 会话日志 356,077 字节 → **409 条事件全部解出**，`tornStart` 为 `undefined`。

### 3.3 Header 形状（实测）

```json
{"type":"session","version":4,"id":"<会话 UUID>",
 "createdAt":1791866167608,"cwd":"C:\\Users\\<用户名>\\Desktop\\program\\personal\\<项目名>",
 "isSeeded":false,"delegationDepth":0,"agentPreset":"standard"}
```

### 3.4 事件信封（实测）

```json
{"type":"tool/call","seq":28,"time":1791812338330,"data":{...}}
```

### 3.5 事件词表（来自 `@deepseek-ai/dsh-session` 的 `KNOWN_SESSION_EVENT_TYPES`，生成文件，权威）

```
agent-preset/selected      agent/inbox/spliced        approval/asked
approval/decided           approval/policy            assistant/attempt
assistant/message          command/done               command/run
compaction/end             compaction/prune           compaction/start
compaction/summary         deliverables/presented     developer/message
feedback/message-delete    feedback/message-put       feedback/record
goal/change                hook/invoked               hook/result
image/offload              llm/retry                  llm/retry-started
model/selection            permission/preset          plan/mode
request/context            request/header             sandbox/mode
schedule/change            session-log-deepseek/delivery-accepted
session/end-seed           session/title              session/title-llm-request
step/end                   step/start                 subagent/catalog
subagent/descriptor        subagent/model-selection-policy
system/message             team/member                team/message/delivered
team/message/queued        team/task                  todo/write
tool-workflow/agent-end    tool-workflow/agent-start  tool-workflow/run-end
tool-workflow/run-start    tool/call                  tool/ptc-dispatch
tool/ptc-dispatch-start    tool/result                turn/end
turn/start                 user/message               web/deepseek-search-llm-request
workspace/changes
```

本项目实际消费并映射的事件（其余类型只计入「其他事件」计数，保证不丢信息也不瞎解释）：

| 事件 | 载荷（实测/类型定义） | 用途 |
| --- | --- | --- |
| `turn/start` | `{ turn: number }` | 会话状态 → 运行中 |
| `turn/end` | `{ turn, reason: TurnEndReason }` | 状态 → 空闲/失败/中断/取消 |
| `step/start` `step/end` | `{ turn, step }` | 当前阶段（第 N 轮第 M 步） |
| `tool/call` | `{ turn, step, callId, name, arguments }`（`arguments` 是模型产出的**原始未解析 JSON 字符串**） | 工具调用开始、参数摘要 |
| `tool/result` | `{ turn, step, message, error?, meta? }`，`message.isError` 表示失败 | 工具调用结束、输出摘要 |
| `user/message` | `{ content, source, role, id }` | 时间线「用户」 |
| `assistant/message` | `{ turn, step, message }`（含 `text` / `reasoning` / `tool-call` 内容块） | 时间线「助手」 |
| `command/run` `command/done` | `{ commandId, name, args, source }` / `{ commandId, kind, text }` | 时间线「命令」 |
| `approval/asked` | `{ id, toolName, callId?, reason? }` | **待审批**（无同 id 的 decided 即待办） |
| `approval/decided` | `{ id, outcome }` | 审批结果 |
| `approval/policy` `permission/preset` `sandbox/mode` | `{ policy }` / `{ preset }` / `{ mode }` | 当前权限姿态展示 |
| `session/title` | `{ title, messageSeqs, source }` | 会话标题 |
| `goal/change` | 目标变更（存在才显示） | 目标进度补充 |
| `todo/write` | 待办写入（存在才显示） | 阶段补充信息 |

`TurnEndReason` 变体（类型定义）：`completed` / `aborted` / `blocked` / `error` / `max-tokens` / `interrupted` / `forked`。

### 3.6 已知限制（如实标注）

- 日志是**批量落盘**（每个 append 批次一帧 + fsync），不是逐 token 流；本项目按文件长度变化做增量 tail，**事件延迟通常在毫秒到秒级**，不承诺「逐字实时」。
- 一个 append 批次可能正被写入：这时尾部会出现**撕裂帧**。本项目把撕裂部分留在缓冲区，等下次扫描补全，**不会**把它算成完整帧，也**不会**因为尾部撕裂就停止解码它前面的完整帧（这是实现过程中实测到并修掉的 bug，已有回归测试）。
- 如果中间某个完整帧结构损坏（例如字节被改写），本项目**报错**并只交付损坏点之前已校验的事件，之后的字节不再猜测；错误会一直显示在界面上，直到文件变化。
- 会话日志**不含** DSH 进程自身信息，也不含 Windows 进程 CPU/内存快照中的「全部进程」；本项目只展示 `node` 进程中**命令行可验证属于 DSH** 的那些（PID、启动时间、命令行摘要），不枚举、不上传全部系统进程，也**绝不终止任何进程**。
- 进程视图依赖 WMI：在受限上下文（例如某些沙箱）里 `Get-CimInstance Win32_Process` 会返回 0 条记录，此时本项目**如实报告「进程视图不可用」**，而不是显示一个空列表让人误以为没有 DSH 在跑。
- 同一会话有且只有一个活动写入者；本项目以只读方式打开，不会与 DSH 争锁。
- 历史格式代际（v0–v3）不迁移；本项目只读最高 `vN` 代际（当前为 v4）。

### 3.7 实测覆盖情况（2026-10-13）

对 `%USERPROFILE%\.dsh\sessions` 下全部 **27 个** v4 会话文件做完整解码：

- 27/27 解码到文件末尾，**无字节缺口**；
- 累计 **2898** 条事件；
- 其中 `approval/asked` 与 `approval/decided` 各 6 条、按 id 全部配对成功。实测样例（真实事件，非构造）：

```json
{"type":"approval/asked","seq":…,"time":…,"data":{
  "id":"ae54cb14-e6ba-4962-885a-90f030033186",
  "toolName":"pwsh",
  "callId":"call_00_ET_VPsZ8KRUOkcI3YV7rRuG2755",
  "reason":"escalate sandbox to danger-full-access: …"}}
```

这条样例证实了 `approval/asked` 会携带 `toolName`、`callId` 与 `reason`，本项目「有 asked 且无同 id 的 decided = 待审批」的判定依据成立。

## 4. 模式 B（临时公网访问）：只有接口，没有实现

- 首期状态恒为 `disabled / not configured`。
- 调用启动接口只会得到明确的「尚未实现」错误。
- 不下载/安装/运行任何隧道客户端，不暴露公网 URL，不改防火墙，不做端口转发/UPnP。
- 代码位置：`backend/src/services/public-access.ts`，类型：`shared/types/public-access.ts`。

## 5. 安全边界（本项目自己的）

- 手机浏览器**只持有本项目签发的受限令牌**，永远拿不到 DSH 的 launch token、cookie 或任何 DSH 凭证。
- 后端不代理 DSH 的 `/api`，不提供聊天输入、不提供命令输入、不提供通用 RPC 转发。
- HTTP + 局域网**不等于安全**：同网段的其他人可以嗅探明文流量。本项目用 Origin 校验、CSRF 防护、速率限制、一次性配对码和最小权限令牌降低风险，但**不宣称局域网是安全的**。详见 README「安全边界」。

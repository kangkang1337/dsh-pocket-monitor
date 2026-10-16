<script setup lang="ts">
/**
 * Settings: device identity, unbinding, access scope (LAN or public), the
 * remembered access PIN, and a connection diagnosis. Nothing here can start a
 * tunnel or change DSH.
 */
import { computed, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { formatDateTime } from '../utils/format.ts'
import { api, rememberedPin } from '../services/api.ts'

const state = monitor.state
const confirming = ref(false)
const diagnostics = ref<string[]>([])
const runningDiagnostics = ref(false)
const accessUrls = ref<string[]>([])
const pinRemembered = ref(rememberedPin() !== undefined)

const device = computed(() => state.device)
const publicAccess = computed(() => state.publicAccess)

/** Drop the remembered PIN so the next public visit asks again. */
function forgetPin(): void {
  monitor.forgetPin()
  pinRemembered.value = false
}

/** Ask the server which addresses it is reachable on. */
async function loadAddresses(): Promise<void> {
  try {
    const probe = await api.pairingProbe()
    accessUrls.value = [...probe.lanUrls]
  } catch {
    accessUrls.value = []
  }
}
void loadAddresses()

/** Run the connection diagnosis the README describes, using real requests. */
async function runDiagnostics(): Promise<void> {
  runningDiagnostics.value = true
  const lines: string[] = []
  try {
    const health = await api.health()
    lines.push(`本地服务：可访问（HTTP 200，version ${health.version}）`)
  } catch (error) {
    lines.push(`本地服务：不可访问（${error instanceof Error ? error.message : String(error)}）`)
  }
  try {
    const status = await api.status()
    lines.push(`设备会话：有效（当前会话 ${status.currentSessionId ?? '无'}）`)
    lines.push(`数据源：${status.source.status} — ${status.source.message}`)
    lines.push(`会话日志根目录：${status.source.sessionsRoot}`)
    if (status.source.projectDir !== undefined) lines.push(`本工作目录的项目目录：${status.source.projectDir}`)
    if (status.source.lastError !== undefined) lines.push(`数据源错误：${status.source.lastError}`)
    lines.push(`匹配到的会话数：${status.sessions.length}`)
  } catch (error) {
    lines.push(`状态接口：失败（${error instanceof Error ? error.message : String(error)}）`)
  }
  lines.push(`实时连接：${monitor.linkText.value}`)
  diagnostics.value = lines
  runningDiagnostics.value = false
}
</script>

<template>
  <section class="settings">
    <h2 class="section__title">设置</h2>

    <div class="card">
      <h3 class="card__title">这台设备</h3>
      <dl class="facts" v-if="device">
        <div><dt>名称</dt><dd>{{ device.name }}</dd></div>
        <div><dt>设备 ID</dt><dd class="mono">{{ device.id.slice(0, 12) }}</dd></div>
        <div><dt>绑定于</dt><dd>{{ formatDateTime(device.createdAt) }}</dd></div>
        <div><dt>最近使用</dt><dd>{{ formatDateTime(device.lastSeenAt) }}</dd></div>
        <div><dt>权限</dt><dd>{{ device.scopes.join('、') }}</dd></div>
      </dl>
      <p class="card__text" v-else>还没有绑定设备。</p>

      <template v-if="!confirming">
        <button class="btn btn--ghost" @click="confirming = true">解除绑定（退出监控）</button>
      </template>
      <template v-else>
        <p class="warn-text">解除绑定后这台手机需要重新扫码配对，电脑端也会立刻断开它的实时连接。</p>
        <div class="row">
          <button class="btn btn--danger" :disabled="state.busy" @click="monitor.unbind(); confirming = false">确认解绑</button>
          <button class="btn btn--ghost" @click="confirming = false">取消</button>
        </div>
      </template>
    </div>

    <div class="card">
      <h3 class="card__title">访问地址</h3>
      <ul class="urls" v-if="accessUrls.length > 0">
        <li v-for="url in accessUrls" :key="url" class="mono">{{ url }}</li>
      </ul>
      <p class="card__text" v-else>暂时读不到地址列表。</p>
      <p class="card__text muted">
        手机必须和电脑在同一个局域网（同一 Wi-Fi）。如果打不开，请检查电脑上的 Windows 防火墙是否放行了本程序端口。
      </p>
    </div>

    <div class="card">
      <h3 class="card__title">访问范围</h3>
      <p class="card__text">
        当前状态：<strong>{{ publicAccess?.mode === 'active' ? '局域网 + 公网' : '仅局域网' }}</strong>
      </p>
      <p class="card__text muted" v-if="publicAccess?.url">公网域名：{{ publicAccess.url }}</p>
      <p class="card__text muted">{{ publicAccess?.reason }}</p>
      <p class="card__text muted">
        公网模式需要你自备隧道（Cloudflare Tunnel / ngrok / Tailscale / 反向代理）并显式开启；
        本服务不会下载、安装或启动任何隧道客户端，也不会改防火墙。已配对的设备换网络后仍可访问，
        未配对的设备一律被拒绝；从公网访问时还需要电脑端生成的访问 PIN。
      </p>
      <template v-if="pinRemembered">
        <button class="btn btn--ghost" @click="forgetPin">清除本机记住的访问 PIN</button>
      </template>
    </div>

    <div class="card">
      <h3 class="card__title">连接诊断</h3>
      <button class="btn btn--ghost" :disabled="runningDiagnostics" @click="runDiagnostics">
        {{ runningDiagnostics ? '检测中…' : '运行诊断' }}
      </button>
      <pre class="diag" v-if="diagnostics.length > 0">{{ diagnostics.join('\n') }}</pre>
    </div>

    <div class="card">
      <h3 class="card__title">安全边界（请读一遍）</h3>
      <ul class="bullets">
        <li>手机只持有本服务签发的受限令牌，拿不到 DSH 的任何凭证。</li>
        <li>本服务只读 DSH 的会话日志，不代理 DSH 的接口，**不提供聊天、命令或任意 RPC**。</li>
        <li>局域网是明文 HTTP：同一 Wi-Fi 下的其他人理论上可以嗅探流量。不要在不可信的公共网络上使用。</li>
        <li>退出程序后服务立即停止，临时配对码同时失效。</li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.settings {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.card {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 14px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.card__title {
  margin: 0;
  font-size: 14px;
}

.card__text {
  margin: 0;
  font-size: 12px;
  line-height: 1.65;
}

.card__text.muted,
.muted {
  color: var(--muted);
}

.facts {
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
}

.facts div {
  display: flex;
  gap: 8px;
}

.facts dt {
  flex: 0 0 72px;
  color: var(--muted);
}

.facts dd {
  margin: 0;
  word-break: break-word;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
  word-break: break-all;
}

.urls {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.row {
  display: flex;
  gap: 8px;
}

.warn-text {
  margin: 0;
  font-size: 12px;
  color: var(--warn);
  line-height: 1.6;
}

.diag {
  margin: 0;
  padding: 10px;
  border-radius: 10px;
  background: var(--field);
  font-size: 11px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
}

.bullets {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  line-height: 1.75;
  color: var(--muted);
}
</style>

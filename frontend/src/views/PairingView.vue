<script setup lang="ts">
/**
 * Pairing screen: the phone side of the one-shot LAN pairing flow.
 *
 * The phone asks for the 6-digit code shown on the desktop, submits it with a
 * secret it generates locally, then waits for the desktop to confirm. No DSH
 * credential is ever part of this flow.
 */
import { computed, onMounted, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { formatDateTime } from '../utils/format.ts'

const code = ref('')
const input = ref<HTMLInputElement | null>(null)

const state = monitor.state
const busy = computed(() => state.busy || state.pairingStatus === 'claiming')
const canSubmit = computed(() => code.value.trim().length === 6 && !busy.value)
const expiresAt = computed(() => state.pairing?.expiresAt ?? null)

/**
 * Accept a code from a scanned QR (`?pair=123456`) and submit it automatically.
 * The code still has to be confirmed on the desktop, so the link alone is not a
 * credential.
 */
onMounted(() => {
  const params = new URLSearchParams(window.location.search)
  const fromQr = (params.get('pair') ?? '').replace(/\D+/g, '').slice(0, 6)
  if (fromQr.length !== 6) {
    input.value?.focus()
    return
  }
  code.value = fromQr
  // Keep the pairing code out of the address bar once it has been used.
  window.history.replaceState({}, '', window.location.pathname)
  void monitor.claimPairing(fromQr)
})

/** Normalise input to digits only. */
function onInput(event: Event): void {
  const target = event.target as HTMLInputElement
  code.value = target.value.replace(/\D+/g, '').slice(0, 6)
}

/** Submit the pairing code. */
function submit(): void {
  if (!canSubmit.value) return
  void monitor.claimPairing(code.value)
}

/** Re-check whether the desktop still has a live code. */
function retry(): void {
  code.value = ''
  void monitor.refreshPairingProbe()
  input.value?.focus()
}
</script>

<template>
  <main class="pairing">
    <header class="pairing__head">
      <h1>DSH Pocket Monitor</h1>
      <p class="pairing__sub">只读监控：查看 Windows 上 DSH 的任务状态。不能聊天，也不能执行命令。</p>
    </header>

    <section class="card">
      <h2 class="card__title">1. 在电脑上查看配对码</h2>
      <p class="card__text">
        在运行服务的电脑终端里，二维码上方会显示 <strong>本次配对码</strong>（6 位数字），有效期几分钟，用过即失效。
      </p>
      <p class="card__meta" v-if="expiresAt !== null">
        电脑端当前配对码有效期至 {{ formatDateTime(expiresAt) }}
      </p>
      <p class="card__meta card__meta--warn" v-else-if="state.pairing && !state.pairing.pairingOpen">
        电脑端当前没有有效配对码。请在服务终端按 <code>r</code> 生成新码后重试。
      </p>
    </section>

    <section class="card">
      <h2 class="card__title">2. 输入配对码</h2>
      <label class="field">
        <span class="field__label">配对码</span>
        <input
          ref="input"
          class="field__input"
          inputmode="numeric"
          autocomplete="one-time-code"
          maxlength="6"
          placeholder="000000"
          :value="code"
          :disabled="busy || state.pairingStatus === 'waiting-approval'"
          @input="onInput"
          @keyup.enter="submit"
        />
      </label>
      <label class="field">
        <span class="field__label">设备名称（显示在电脑端的确认提示里）</span>
        <input class="field__input field__input--text" v-model="state.deviceName" maxlength="40" />
      </label>
      <button class="btn btn--primary" :disabled="!canSubmit" @click="submit">
        {{ busy ? '正在提交…' : '提交配对请求' }}
      </button>
    </section>

    <section class="card" v-if="state.pairingStatus === 'waiting-approval'">
      <h2 class="card__title">3. 在电脑上确认</h2>
      <p class="card__text">请求已提交，正在等待电脑端确认。请在那台电脑上操作：</p>
      <ul class="steps">
        <li>服务终端里按 <code>a</code> 回车确认（按 <code>x</code> 拒绝）；</li>
        <li>或者在任意终端运行 <code>npm run approve</code>。</li>
      </ul>
      <p class="card__meta">本页面会自动刷新，确认后立刻进入监控界面。</p>
    </section>

    <p class="alert alert--bad" v-if="state.pairingStatus === 'failed' || state.pairingMessage">
      {{ state.pairingMessage }}
    </p>

    <p class="alert" v-if="state.error">{{ state.error }}</p>

    <footer class="pairing__foot">
      <button class="btn btn--ghost" @click="retry">我拿到新配对码了，重试</button>
      <p class="pairing__note">
        本服务只在局域网内监听，手机与电脑需要连接同一个 Wi-Fi。退出程序后服务立即停止。
      </p>
    </footer>
  </main>
</template>

<style scoped>
.pairing {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px 16px calc(28px + env(safe-area-inset-bottom));
  max-width: 560px;
  margin: 0 auto;
}

.pairing__head h1 {
  margin: 0 0 6px;
  font-size: 22px;
  letter-spacing: -0.01em;
}

.pairing__sub {
  margin: 0;
  font-size: 13px;
  color: var(--muted);
  line-height: 1.55;
}

.card {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 14px;
  padding: 14px 14px 16px;
}

.card__title {
  margin: 0 0 8px;
  font-size: 15px;
}

.card__text {
  margin: 0 0 8px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--text);
}

.card__meta {
  margin: 6px 0 0;
  font-size: 12px;
  color: var(--muted);
}

.card__meta--warn {
  color: var(--warn);
}

.field {
  display: block;
  margin-bottom: 12px;
}

.field__label {
  display: block;
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
}

.field__input {
  width: 100%;
  box-sizing: border-box;
  padding: 14px 12px;
  font-size: 26px;
  letter-spacing: 0.35em;
  text-align: center;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: var(--field);
  color: var(--text);
}

.field__input--text {
  font-size: 16px;
  letter-spacing: normal;
  text-align: left;
}

.field__input:focus {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}

.steps {
  margin: 6px 0 0;
  padding-left: 18px;
  font-size: 13px;
  line-height: 1.7;
  color: var(--text);
}

code {
  background: var(--field);
  border-radius: 5px;
  padding: 1px 5px;
  font-size: 12px;
}

.alert {
  margin: 0;
  padding: 12px;
  border-radius: 12px;
  font-size: 13px;
  line-height: 1.6;
  background: var(--warn-bg);
  color: var(--warn);
  border: 1px solid var(--warn-line);
}

.alert--bad {
  background: var(--bad-bg);
  color: var(--bad);
  border-color: var(--bad-line);
}

.pairing__foot {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-top: 4px;
}

.pairing__note {
  margin: 0;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.6;
}
</style>

<script setup lang="ts">
/**
 * Public-access PIN prompt.
 *
 * Shown when this phone reaches the monitor from another network: the device
 * token alone is not enough there, so the server asks for the second factor.
 * The PIN is remembered on this phone afterwards.
 */
import { computed, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'

const state = monitor.state
const pin = ref('')
const input = ref<HTMLInputElement | null>(null)

const canSubmit = computed(() => pin.value.trim().length >= 4 && !state.busy)

/** Digits only, 4-12 characters — the shape the backend accepts. */
function onInput(event: Event): void {
  const target = event.target as HTMLInputElement
  pin.value = target.value.replace(/\D+/g, '').slice(0, 12)
}

/** Submit and continue. */
function submit(): void {
  if (!canSubmit.value) return
  void monitor.submitPin(pin.value)
}
</script>

<template>
  <main class="pin">
    <header class="pin__head">
      <h1>需要访问 PIN</h1>
      <p class="pin__sub">
        这台手机正在从另一个网络访问监控服务。除了设备令牌，公网访问还需要电脑端生成的访问 PIN（第二道验证）。
      </p>
    </header>

    <section class="card">
      <p class="card__reason" v-if="state.pinMessage">{{ state.pinMessage }}</p>
      <label class="field">
        <span class="field__label">访问 PIN（4-12 位数字）</span>
        <input
          ref="input"
          class="field__input"
          inputmode="numeric"
          autocomplete="one-time-code"
          placeholder="······"
          :value="pin"
          :disabled="state.busy"
          @input="onInput"
          @keyup.enter="submit"
        />
      </label>
      <button class="btn btn--primary" :disabled="!canSubmit" @click="submit">
        {{ state.busy ? '验证中…' : '验证并继续' }}
      </button>
      <p class="card__hint">
        忘记 PIN？在运行服务的电脑上执行 <code>npm run pin</code> 查看说明，或重新生成一个。
      </p>
    </section>

    <p class="alert" v-if="state.error">{{ state.error }}</p>
  </main>
</template>

<style scoped>
.pin {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 22px 16px calc(28px + env(safe-area-inset-bottom));
  max-width: 520px;
  margin: 0 auto;
}

.pin__head h1 {
  margin: 0 0 6px;
  font-size: 21px;
}

.pin__sub {
  margin: 0;
  font-size: 13px;
  line-height: 1.6;
  color: var(--muted);
}

.card {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 14px;
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.card__reason {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--warn-line);
  background: var(--warn-bg);
  color: var(--warn);
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
  font-size: 22px;
  letter-spacing: 0.3em;
  text-align: center;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: var(--field);
  color: var(--text);
}

.card__hint {
  margin: 0;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.6;
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
  background: var(--bad-bg);
  color: var(--bad);
  border: 1px solid var(--bad-line);
}
</style>

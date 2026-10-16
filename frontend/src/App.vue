<script setup lang="ts">
/**
 * Application shell: loading, error, pairing, or monitoring.
 */
import { onMounted, onUnmounted } from 'vue'
import { monitor } from './stores/monitor.ts'
import PairingView from './views/PairingView.vue'
import MonitorView from './views/MonitorView.vue'
import PinPrompt from './views/PinPrompt.vue'

const state = monitor.state

onMounted(() => {
  void monitor.initialise()
})
onUnmounted(() => {
  monitor.dispose()
})
</script>

<template>
  <div class="app">
    <!-- A public-network PIN refusal takes priority: nothing else can load. -->
    <PinPrompt v-if="state.pinRequired" />

    <div class="loading" v-else-if="state.phase === 'loading'">
      <p class="loading__title">正在连接本地监控服务…</p>
      <p class="loading__hint">如果你还没在电脑上启动程序，请先运行 <code>npm run start:lan</code>。</p>
    </div>

    <div class="loading" v-else-if="state.phase === 'error'">
      <p class="loading__title">连接失败</p>
      <p class="loading__hint">{{ state.error }}</p>
      <ul class="tips">
        <li>确认电脑上的服务仍在运行，手机与电脑在同一个 Wi-Fi。</li>
        <li>确认地址里的 IP 与端口和电脑终端里打印的一致。</li>
        <li>还不行就检查 Windows 防火墙是否放行了这个端口。</li>
      </ul>
      <button class="btn btn--primary" @click="monitor.initialise()">重新连接</button>
    </div>

    <PairingView v-else-if="state.phase === 'pairing'" />
    <MonitorView v-else />
  </div>
</template>

<style scoped>
.app {
  min-height: 100dvh;
}

.loading {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 28px 18px;
  max-width: 480px;
  margin: 0 auto;
}

.loading__title {
  margin: 0;
  font-size: 17px;
  font-weight: 700;
}

.loading__hint {
  margin: 0;
  font-size: 13px;
  line-height: 1.65;
  color: var(--muted);
}

.tips {
  margin: 0;
  padding-left: 18px;
  font-size: 12px;
  line-height: 1.8;
  color: var(--muted);
}

code {
  background: var(--field);
  border-radius: 5px;
  padding: 1px 5px;
  font-size: 12px;
}
</style>

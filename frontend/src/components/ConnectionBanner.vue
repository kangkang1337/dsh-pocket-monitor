<script setup lang="ts">
/**
 * Connection banner: distinguishes the phone-to-server link from the DSH data
 * source, and offers a manual retry. Shows a clear text status, not just colour.
 */
import { computed } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { sourceStatusLabel, statusTone } from '../utils/format.ts'

const state = monitor.state
const source = computed(() => state.status?.source)
const tone = computed(() => (state.link === 'open' ? statusTone(source.value?.status ?? 'idle') : 'bad'))
const offline = computed(() => state.link !== 'open')

/** Force an immediate refresh. */
function retry(): void {
  void monitor.refreshStatus(true)
}
</script>

<template>
  <div class="banner" :class="`banner--${tone}`" role="status">
    <span class="banner__icon">{{ tone === 'ok' ? '●' : tone === 'bad' ? '✕' : '⚠' }}</span>
    <div class="banner__text">
      <span class="banner__title">{{ monitor.linkText.value }}</span>
      <span class="banner__sub">
        DSB 数据源：{{ sourceStatusLabel(source?.status ?? 'idle') }}
        <template v-if="source">— {{ source.message }}</template>
      </span>
    </div>
    <button class="banner__action" v-if="offline" @click="retry">重试</button>
  </div>
</template>

<style scoped>
.banner {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 9px 12px;
  border-radius: 12px;
  border: 1px solid var(--line);
  background: var(--card);
  font-size: 12px;
}

.banner--ok {
  border-color: var(--ok-line);
  background: var(--ok-bg);
}

.banner--warn {
  border-color: var(--warn-line);
  background: var(--warn-bg);
}

.banner--bad {
  border-color: var(--bad-line);
  background: var(--bad-bg);
}

.banner__icon {
  flex: 0 0 auto;
  font-size: 12px;
}

.banner--ok .banner__icon {
  color: var(--ok);
}

.banner--warn .banner__icon {
  color: var(--warn);
}

.banner--bad .banner__icon {
  color: var(--bad);
}

.banner__text {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
  flex: 1 1 auto;
}

.banner__title {
  font-weight: 600;
}

.banner__sub {
  color: var(--muted);
  font-size: 11px;
  line-height: 1.5;
}

.banner__action {
  flex: 0 0 auto;
  border: 1px solid currentColor;
  background: transparent;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 11px;
  color: inherit;
  cursor: pointer;
}
</style>

<script setup lang="ts">
/**
 * Status overview card: what the backend can actually confirm about the DSH
 * source and the current session. No invented percentages — only phase, last
 * activity, and elapsed time read from the session log.
 */
import { computed, onUnmounted, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { formatAgo, formatClock, formatDuration, sessionStateLabel, sessionStateTone, sourceStatusLabel, statusTone } from '../utils/format.ts'

const state = monitor.state
const now = ref(Date.now())
const ticker = window.setInterval(() => {
  now.value = Date.now()
}, 1_000)
onUnmounted(() => window.clearInterval(ticker))

const session = computed(() => monitor.currentSession.value)
const source = computed(() => state.status?.source)
const ageText = computed(() => (session.value === undefined ? '—' : formatAgo(session.value.lastEventAt, now.value)))
const runDuration = computed(() => {
  if (session.value === undefined) return '—'
  if (session.value.runDurationMs !== undefined) return formatDuration(session.value.runDurationMs)
  return '未在运行'
})
const lastEventClock = computed(() => (session.value === undefined ? '—' : formatClock(session.value.lastEventAt)))
</script>

<template>
  <section class="overview">
    <div class="overview__grid">
      <div class="tile">
        <span class="tile__label">DSH 数据源</span>
        <span class="tile__value">
          <span class="badge" :class="`badge--${statusTone(source?.status ?? 'idle')}`">
            {{ sourceStatusLabel(source?.status ?? 'idle') }}
          </span>
        </span>
        <span class="tile__hint">{{ source?.message }}</span>
      </div>

      <div class="tile">
        <span class="tile__label">当前会话</span>
        <span class="tile__value">{{ session?.title ?? session?.sessionId?.slice(0, 20) ?? '暂无会话' }}</span>
        <span class="tile__hint" v-if="session">
          <span class="badge" :class="`badge--${sessionStateTone(session.state)}`">{{ sessionStateLabel(session.state) }}</span>
          {{ session.stateReason }}
        </span>
        <span class="tile__hint" v-else>还没有在这个工作目录里检测到 DSH 会话日志。</span>
      </div>

      <div class="tile">
        <span class="tile__label">当前阶段</span>
        <span class="tile__value" v-if="session?.turn !== undefined">
          第 {{ session.turn }} 轮<span v-if="session.step !== undefined"> · 第 {{ session.step }} 步</span>
        </span>
        <span class="tile__value" v-else>—</span>
        <span class="tile__hint">DSH 不提供整体完成度百分比，这里只显示日志能确认的阶段。</span>
      </div>

      <div class="tile">
        <span class="tile__label">本轮运行时长</span>
        <span class="tile__value">{{ runDuration }}</span>
        <span class="tile__hint">最近活动：{{ lastEventClock }}（{{ ageText }}）</span>
      </div>
    </div>

    <div class="meta" v-if="session">
      <span class="meta__item">事件 {{ session.eventCount }} 条</span>
      <span class="meta__item" v-if="session.approvalPolicy">审批策略 {{ session.approvalPolicy }}</span>
      <span class="meta__item" v-if="session.permissionPreset">权限 {{ session.permissionPreset }}</span>
      <span class="meta__item" v-if="session.sandboxMode">沙箱 {{ session.sandboxMode }}</span>
      <span class="meta__item">日志格式 v{{ session.formatVersion }}</span>
      <span class="meta__item">{{ session.live ? '日志正在追加' : '日志当前无追加' }}</span>
    </div>

    <div class="tools" v-if="session && session.currentTools.length > 0">
      <h3 class="tools__title">正在执行的工具调用</h3>
      <ul class="tools__list">
        <li class="tool" v-for="tool in session.currentTools" :key="tool.callId">
          <span class="tool__name">{{ tool.name }}</span>
          <span class="tool__arg">{{ tool.argumentsSummary }}</span>
          <span class="tool__meta">第 {{ tool.turn }} 轮第 {{ tool.step }} 步 · 已运行 {{ formatDuration(now - tool.startedAt) }}</span>
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.overview {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.overview__grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}

@media (max-width: 380px) {
  .overview__grid {
    grid-template-columns: 1fr;
  }
}

.tile {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 14px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-height: 84px;
}

.tile__label {
  font-size: 11px;
  color: var(--muted);
  letter-spacing: 0.02em;
}

.tile__value {
  font-size: 15px;
  font-weight: 600;
  line-height: 1.35;
  word-break: break-word;
}

.tile__hint {
  font-size: 11px;
  color: var(--muted);
  line-height: 1.5;
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.meta__item {
  font-size: 11px;
  color: var(--muted);
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 3px 9px;
  background: var(--card);
}

.tools {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 14px;
  padding: 12px;
}

.tools__title {
  margin: 0 0 8px;
  font-size: 13px;
}

.tools__list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.tool {
  border-left: 3px solid var(--accent);
  padding-left: 9px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.tool__name {
  font-size: 13px;
  font-weight: 600;
}

.tool__arg {
  font-size: 12px;
  color: var(--muted);
  word-break: break-word;
}

.tool__meta {
  font-size: 11px;
  color: var(--muted);
}
</style>

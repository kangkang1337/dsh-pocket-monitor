<script setup lang="ts">
/**
 * Monitoring screen: sticky header (identity + approvals badge + link state),
 * session switcher, and the tabbed panels. There is deliberately no chat box,
 * no command input, and no terminal — the phone can only read and decide.
 */
import { computed, onMounted, ref } from 'vue'
import { monitor, normaliseWorkspace } from '../stores/monitor.ts'
import { shortTitle, sessionStateLabel } from '../utils/format.ts'
import ConnectionBanner from '../components/ConnectionBanner.vue'
import StatusOverview from '../components/StatusOverview.vue'
import Timeline from '../components/Timeline.vue'
import ProcessView from '../components/ProcessView.vue'
import ApprovalPanel from '../components/ApprovalPanel.vue'
import SettingsPanel from '../components/SettingsPanel.vue'

type Tab = 'status' | 'activity' | 'processes' | 'approvals' | 'settings'

const state = monitor.state
const tab = ref<Tab>('status')
const pendingCount = computed(() => monitor.pendingApprovals.value.length)

/** Level one: workspaces that currently have sessions. */
const workspaceGroups = computed(() => monitor.workspaces.value)
/** Level two: sessions inside the selected workspace. */
const visibleSessions = computed(() => monitor.visibleSessions.value)
const activeWorkspaceKey = computed(() => {
  const selected = state.selectedSessionId
  const session = state.status?.sessions.find((entry) => entry.sessionId === selected)
  if (session !== undefined) return normaliseWorkspace(session.cwd)
  return workspaceGroups.value[0]?.key
})

const tabs: Array<{ id: Tab; label: string; badge?: number }> = [
  { id: 'status', label: '概览' },
  { id: 'activity', label: '时间线' },
  { id: 'processes', label: '进程' },
  { id: 'approvals', label: '审批' },
  { id: 'settings', label: '设置' },
]

onMounted(() => {
  void monitor.refreshApprovals()
})

/** Show a session and load its timeline when needed. */
function pick(sessionId: string): void {
  monitor.selectSession(sessionId)
}

/** Short state text for a session chip (text, not colour alone). */
function stateLabel(value: string): string {
  return sessionStateLabel(value)
}
</script>

<template>
  <div class="shell">
    <header class="topbar">
      <div class="topbar__row">
        <div class="topbar__title">
          <span class="brand">DSH 监控</span>
          <span class="device">{{ state.device?.name ?? '' }}</span>
        </div>
        <div class="topbar__meta">
          <span class="dot" :class="monitor.connected.value ? 'dot--ok' : 'dot--bad'">{{
            monitor.connected.value ? '实时' : '离线'
          }}</span>
          <span v-if="pendingCount > 0" class="dot dot--warn">审批 {{ pendingCount }}</span>
        </div>
      </div>
      <ConnectionBanner />

      <nav class="tabs tabs--workspace" v-if="workspaceGroups.length > 1" aria-label="工作目录">
        <button
          v-for="group in workspaceGroups"
          :key="group.key"
          class="tab-chip tab-chip--project"
          :class="{ 'tab-chip--active': group.key === activeWorkspaceKey }"
          @click="monitor.selectWorkspace(group.key)"
          :title="group.fullPath"
        >
          {{ group.label }}
          <span class="tab-chip__count">{{ group.sessions.length }}</span>
          <span v-if="group.runningCount > 0" class="tab-chip__live" aria-label="有会话在运行">●</span>
        </button>
      </nav>

      <nav class="tabs" v-if="visibleSessions.length > 1" aria-label="会话">
        <button
          v-for="session in visibleSessions"
          :key="session.sessionId"
          class="tab-chip"
          :class="{ 'tab-chip--active': session.sessionId === monitor.currentSession.value?.sessionId }"
          @click="pick(session.sessionId)"
        >
          {{ shortTitle(session.title, session.sessionId.slice(0, 10)) }}
          <span class="tab-chip__state" :class="'tab-chip__state--' + session.state">{{ stateLabel(session.state) }}</span>
        </button>
      </nav>
    </header>

    <main class="content">
      <p class="notice" v-if="state.notice">
        {{ state.notice }}
        <button class="notice__close" @click="monitor.clearNotice()">知道了</button>
      </p>
      <p class="alert" v-if="state.error">{{ state.error }}</p>

      <StatusOverview v-if="tab === 'status'" />
      <Timeline v-else-if="tab === 'activity'" />
      <ProcessView v-else-if="tab === 'processes'" />
      <ApprovalPanel v-else-if="tab === 'approvals'" />
      <SettingsPanel v-else />
    </main>

    <nav class="tabbar">
      <button
        v-for="entry in tabs"
        :key="entry.id"
        class="tabbar__item"
        :class="{ 'tabbar__item--active': tab === entry.id }"
        @click="tab = entry.id"
      >
        <span class="tabbar__label">{{ entry.label }}</span>
        <span v-if="entry.id === 'approvals' && pendingCount > 0" class="tabbar__badge">{{ pendingCount }}</span>
      </button>
    </nav>
  </div>
</template>

<style scoped>
.shell {
  display: flex;
  flex-direction: column;
  min-height: 100dvh;
  max-width: 620px;
  margin: 0 auto;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 5;
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: calc(10px + env(safe-area-inset-top)) 14px 10px;
  background: color-mix(in srgb, var(--bg) 92%, transparent);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--line);
}

.topbar__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.topbar__title {
  display: flex;
  align-items: baseline;
  gap: 8px;
  min-width: 0;
}

.brand {
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -0.01em;
}

.device {
  font-size: 11px;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.topbar__meta {
  display: flex;
  gap: 6px;
  flex: 0 0 auto;
}

.dot {
  font-size: 10px;
  padding: 3px 8px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--muted);
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.dot--ok {
  color: var(--ok);
  border-color: var(--ok-line);
  background: var(--ok-bg);
}

.dot--bad {
  color: var(--bad);
  border-color: var(--bad-line);
  background: var(--bad-bg);
}

.dot--warn {
  color: var(--warn);
  border-color: var(--warn-line);
  background: var(--warn-bg);
}

.tabs {
  display: flex;
  gap: 6px;
  overflow-x: auto;
  padding-bottom: 2px;
  scrollbar-width: none;
}

.tabs::-webkit-scrollbar {
  display: none;
}

.tab-chip {
  flex: 0 0 auto;
  font-size: 11px;
  padding: 5px 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--card);
  color: var(--muted);
}

.tab-chip--active {
  border-color: var(--accent);
  color: var(--accent);
}

/* Level one: workspace chips are visually distinct from session chips. */
.tabs--workspace {
  margin-bottom: 6px;
}

.tab-chip--project {
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.tab-chip__count {
  font-size: 10px;
  opacity: 0.75;
  border: 1px solid currentColor;
  border-radius: 999px;
  padding: 0 4px;
  line-height: 14px;
}

.tab-chip__live {
  font-size: 9px;
  color: var(--ok, #2e7d32);
}

.tab-chip__state {
  margin-left: 5px;
  font-size: 10px;
  opacity: 0.8;
}

.tab-chip__state--running {
  color: var(--ok, #2e7d32);
  opacity: 1;
}

.tab-chip__state--waiting-approval {
  color: var(--warn, #b26a00);
  opacity: 1;
}

.tab-chip__state--failed,
.tab-chip__state--aborted {
  color: var(--bad, #c62828);
  opacity: 1;
}

.content {
  flex: 1 1 auto;
  padding: 14px 14px 96px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.notice,
.alert {
  margin: 0;
  padding: 11px 12px;
  border-radius: 12px;
  font-size: 12px;
  line-height: 1.6;
  border: 1px solid var(--warn-line);
  background: var(--warn-bg);
  color: var(--warn);
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: flex-start;
}

.notice__close {
  flex: 0 0 auto;
  border: 1px solid currentColor;
  background: transparent;
  color: inherit;
  border-radius: 999px;
  font-size: 11px;
  padding: 2px 8px;
}

.alert {
  border-color: var(--bad-line);
  background: var(--bad-bg);
  color: var(--bad);
}

.tabbar {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  display: flex;
  justify-content: center;
  gap: 2px;
  padding: 6px 8px calc(6px + env(safe-area-inset-bottom));
  background: color-mix(in srgb, var(--bg) 94%, transparent);
  backdrop-filter: blur(12px);
  border-top: 1px solid var(--line);
}

.tabbar__item {
  position: relative;
  flex: 1 1 0;
  max-width: 120px;
  border: none;
  background: transparent;
  color: var(--muted);
  font-size: 11px;
  padding: 8px 4px;
  border-radius: 10px;
}

.tabbar__item--active {
  color: var(--accent);
  background: var(--field);
  font-weight: 600;
}

.tabbar__label {
  display: block;
}

.tabbar__badge {
  position: absolute;
  top: 2px;
  right: 50%;
  transform: translateX(26px);
  background: var(--warn);
  color: var(--bg);
  border-radius: 999px;
  font-size: 10px;
  line-height: 1;
  padding: 2px 5px;
}
</style>

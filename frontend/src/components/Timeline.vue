<script setup lang="ts">
/**
 * Activity timeline with on-demand expansion.
 *
 * Entries are newest-first, collapsed by default, and only the tapped row
 * expands — long DSH logs stay cheap on a phone.
 */
import { computed, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { eventIcon, formatClock } from '../utils/format.ts'

const PAGE_SIZE = 40
const expanded = ref<Set<string>>(new Set())
const showAll = ref(false)

const all = computed(() => monitor.timeline.value)
const events = computed(() => (showAll.value ? all.value : all.value.slice(0, PAGE_SIZE)))
const hiddenCount = computed(() => Math.max(0, all.value.length - events.value.length))

/** Toggle one row's detail. */
function toggle(id: string): void {
  const next = new Set(expanded.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  expanded.value = next
}
</script>

<template>
  <section class="timeline">
    <header class="timeline__head">
      <h2 class="section__title">活动时间线</h2>
      <span class="timeline__count">{{ all.length }} 条</span>
    </header>

    <p class="empty" v-if="all.length === 0">
      还没有事件。DSH 在这个工作目录里开始运行时，事件会自动出现（不需要手动刷新）。
    </p>

    <ul class="events" v-else>
      <li
        v-for="event in events"
        :key="event.id"
        class="event"
        :class="[`event--${event.level}`, { 'event--open': expanded.has(event.id) }]"
        @click="toggle(event.id)"
      >
        <span class="event__icon" :class="`event__icon--${event.level}`">{{ eventIcon(event.kind, event.level) }}</span>
        <div class="event__body">
          <div class="event__row">
            <span class="event__title">{{ event.title }}</span>
            <span class="event__time">{{ formatClock(event.time) }}</span>
          </div>
          <p class="event__detail" v-if="event.detail !== undefined">
            {{ expanded.has(event.id) ? event.detail : event.detail.slice(0, 98) + (event.detail.length > 98 ? '…' : '') }}
          </p>
        </div>
      </li>
    </ul>

    <button class="btn btn--ghost" v-if="hiddenCount > 0 && !showAll" @click="showAll = true">
      显示更早的 {{ hiddenCount }} 条
    </button>
    <button class="btn btn--ghost" v-else-if="showAll && all.length > PAGE_SIZE" @click="showAll = false">
      只看最近 {{ PAGE_SIZE }} 条
    </button>
  </section>
</template>

<style scoped>
.timeline {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.timeline__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
}

.timeline__count {
  font-size: 11px;
  color: var(--muted);
}

.events {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.event {
  display: flex;
  gap: 9px;
  padding: 9px 10px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--card);
  cursor: pointer;
  -webkit-tap-highlight-color: transparent;
}

.event--open {
  border-color: var(--accent);
}

.event--error {
  border-color: var(--bad-line);
}

.event--warn {
  border-color: var(--warn-line);
}

.event__icon {
  flex: 0 0 20px;
  height: 20px;
  width: 20px;
  border-radius: 6px;
  display: grid;
  place-items: center;
  font-size: 11px;
  background: var(--field);
  color: var(--muted);
}

.event__icon--error {
  background: var(--bad-bg);
  color: var(--bad);
}

.event__icon--warn {
  background: var(--warn-bg);
  color: var(--warn);
}

.event__icon--success {
  background: var(--ok-bg);
  color: var(--ok);
}

.event__body {
  flex: 1 1 auto;
  min-width: 0;
}

.event__row {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  align-items: baseline;
}

.event__title {
  font-size: 13px;
  font-weight: 600;
  word-break: break-word;
}

.event__time {
  font-size: 11px;
  color: var(--muted);
  flex: 0 0 auto;
  font-variant-numeric: tabular-nums;
}

.event__detail {
  margin: 4px 0 0;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.55;
  word-break: break-word;
  white-space: pre-wrap;
}

.empty {
  margin: 0;
  padding: 14px;
  border: 1px dashed var(--line);
  border-radius: 12px;
  font-size: 13px;
  color: var(--muted);
  line-height: 1.6;
}
</style>

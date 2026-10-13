<script setup lang="ts">
/**
 * Process view: only processes the backend verified as DSH-related, with the PID
 * and the command line it redacted. Nothing is terminated from here.
 */
import { computed } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { formatDateTime } from '../utils/format.ts'

const state = monitor.state
const processes = computed(() => state.status?.processes ?? [])
const note = computed(() => state.status?.source.processNote)
const scanned = computed(() => state.status?.source.nodeProcessCount)
</script>

<template>
  <section class="processes">
    <h2 class="section__title">相关进程</h2>
    <p class="note">
      只显示命令行可验证属于 DSH 的 <code>node.exe</code> 进程（PID、角色、监听端口）。
      本服务不枚举全部系统进程，也不会上传或终止任何进程。
      <template v-if="scanned !== undefined">本次扫描到 {{ scanned }} 个 node 进程。</template>
    </p>

    <p class="warn" v-if="note">{{ note }}</p>

    <p class="empty" v-if="processes.length === 0">
      没有检测到 DSH 相关进程。如果你还没启动 DSH，这是正常的。
    </p>

    <ul class="list" v-else>
      <li class="proc" v-for="proc in processes" :key="proc.pid">
        <div class="proc__row">
          <span class="proc__name">{{ proc.name }}</span>
          <span class="proc__pid">PID {{ proc.pid }}</span>
        </div>
        <p class="proc__role">{{ proc.role }}</p>
        <p class="proc__started" v-if="proc.startedAt !== undefined">启动于 {{ formatDateTime(proc.startedAt) }}</p>
        <p class="proc__cmd mono">{{ proc.commandLine }}</p>
      </li>
    </ul>
  </section>
</template>

<style scoped>
.processes {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.note {
  margin: 0;
  font-size: 11px;
  line-height: 1.6;
  color: var(--muted);
}

.warn {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid var(--warn-line);
  background: var(--warn-bg);
  color: var(--warn);
}

.empty {
  margin: 0;
  padding: 14px;
  border: 1px dashed var(--line);
  border-radius: 12px;
  font-size: 13px;
  color: var(--muted);
}

.list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.proc {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 12px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.proc__row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.proc__name {
  font-size: 13px;
  font-weight: 600;
}

.proc__pid {
  font-size: 11px;
  color: var(--muted);
  font-variant-numeric: tabular-nums;
}

.proc__role {
  margin: 0;
  font-size: 12px;
}

.proc__started,
.proc__cmd {
  margin: 0;
  font-size: 11px;
  color: var(--muted);
  word-break: break-all;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
</style>

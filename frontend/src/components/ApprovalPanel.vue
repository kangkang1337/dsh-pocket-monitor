<script setup lang="ts">
/**
 * Approval panel.
 *
 * It shows the real pending requests read from the DSH session audit log, and
 * the buttons are deliberately separated from navigation and require a second
 * tap to confirm. When this DSH build has no external approval channel, the
 * backend's explicit refusal is displayed verbatim — the UI never claims a
 * decision was delivered.
 */
import { computed, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { formatAgo, outcomeText } from '../utils/format.ts'

const state = monitor.state
const confirming = ref<{ id: string; action: 'approve' | 'reject' } | undefined>(undefined)
const busyId = ref<string | undefined>(undefined)

const pending = computed(() => monitor.pendingApprovals.value)
const capability = computed(() => state.approvals?.capability ?? state.status?.capabilities.approvalDeciding ?? false)
const capabilityReason = computed(
  () => state.approvals?.capabilityReason ?? state.status?.capabilities.approvalDecidingReason ?? '',
)
const decided = computed(() => state.approvals?.decided ?? state.status?.recentlyDecided ?? [])
const attempts = computed(() => state.approvals?.attempts ?? [])

/** First tap arms the button, second tap submits. */
function arm(id: string, action: 'approve' | 'reject'): void {
  confirming.value = { id, action }
}

/** Submit the armed decision. */
function commit(id: string, action: 'approve' | 'reject'): void {
  confirming.value = undefined
  busyId.value = id
  void monitor.decide(id, action).finally(() => {
    busyId.value = undefined
  })
}

/** Cancel an armed action. */
function cancel(): void {
  confirming.value = undefined
}
</script>

<template>
  <section class="approvals">
    <header class="approvals__head">
      <h2 class="section__title">待审批</h2>
      <span class="pill" :class="pending.length > 0 ? 'pill--warn' : 'pill--idle'">
        {{ pending.length > 0 ? `${pending.length} 项待处理` : '暂无待审批' }}
      </span>
    </header>

    <p class="hint" v-if="!capability">
      <strong>只能查看，不能下发。</strong>{{ capabilityReason }}
    </p>

    <p class="empty" v-if="pending.length === 0">
      当前没有待审批请求。出现审批时这里会自动更新（数据来自 DSH 会话日志里成对的
      <code>approval/asked</code> / <code>approval/decided</code> 事件）。
    </p>

    <ul class="list" v-else>
      <li class="request" v-for="request in pending" :key="request.id">
        <div class="request__head">
          <span class="request__tool">{{ request.toolName }}</span>
          <span class="request__time">{{ formatAgo(request.askedAt) }}</span>
        </div>
        <dl class="request__facts">
          <div><dt>请求 ID</dt><dd class="mono">{{ request.id.slice(0, 12) }}</dd></div>
          <div v-if="request.callId"><dt>工具调用</dt><dd class="mono">{{ request.callId.slice(0, 16) }}</dd></div>
          <div v-if="request.reason"><dt>原因</dt><dd>{{ request.reason }}</dd></div>
          <div v-if="request.policy"><dt>当时策略</dt><dd>{{ request.policy }}</dd></div>
          <div><dt>会话</dt><dd class="mono">{{ request.sessionId.slice(0, 22) }}</dd></div>
        </dl>

        <div class="request__actions">
          <template v-if="confirming !== undefined && confirming.id === request.id">
            <p class="confirm">
              确认要对「{{ request.toolName }}」执行<strong>{{ confirming.action === 'approve' ? '批准' : '拒绝' }}</strong>吗？
            </p>
            <div class="actions-row">
              <button
                class="btn btn--danger"
                :disabled="busyId === request.id"
                @click="commit(request.id, confirming.action)"
              >
                {{ busyId === request.id ? '提交中…' : '确认提交' }}
              </button>
              <button class="btn btn--ghost" @click="cancel">取消</button>
            </div>
          </template>
          <template v-else>
            <button class="btn btn--approve" @click="arm(request.id, 'approve')">批准…</button>
            <button class="btn btn--reject" @click="arm(request.id, 'reject')">拒绝…</button>
          </template>
        </div>
      </li>
    </ul>

    <div class="decided" v-if="decided.length > 0">
      <h3 class="decided__title">最近的审批结果</h3>
      <ul class="decided__list">
        <li v-for="entry in decided.slice(0, 6)" :key="entry.id">
          <span class="decided__outcome">{{ outcomeText(entry.outcome) }}</span>
          <span class="decided__time">{{ formatAgo(entry.decidedAt) }}</span>
        </li>
      </ul>
    </div>

    <div class="decided" v-if="attempts.length > 0">
      <h3 class="decided__title">本机记录的提交尝试（未下发到 DSH）</h3>
      <ul class="decided__list">
        <li v-for="entry in attempts.slice(0, 5)" :key="`${entry.approvalId}-${entry.at}`">
          <span class="decided__outcome">{{ entry.action === 'approve' ? '批准意图' : '拒绝意图' }} · {{ entry.reason }}</span>
          <span class="decided__time">{{ formatAgo(entry.at) }}</span>
        </li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.approvals {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.approvals__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
}

.hint {
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
  line-height: 1.6;
}

.list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.request {
  border: 1px solid var(--warn-line);
  background: var(--card);
  border-radius: 14px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.request__head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.request__tool {
  font-size: 15px;
  font-weight: 700;
}

.request__time {
  font-size: 11px;
  color: var(--muted);
}

.request__facts {
  margin: 0;
  display: grid;
  grid-template-columns: 1fr;
  gap: 4px;
  font-size: 12px;
}

.request__facts div {
  display: flex;
  gap: 8px;
}

.request__facts dt {
  color: var(--muted);
  flex: 0 0 64px;
}

.request__facts dd {
  margin: 0;
  word-break: break-word;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11px;
}

.request__actions {
  display: flex;
  flex-direction: column;
  gap: 8px;
  border-top: 1px dashed var(--line);
  padding-top: 10px;
}

.actions-row {
  display: flex;
  gap: 8px;
}

.confirm {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text);
}

.decided__title {
  margin: 0 0 6px;
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

.decided__list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12px;
}

.decided__list li {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}

.decided__time {
  color: var(--muted);
  flex: 0 0 auto;
}
</style>

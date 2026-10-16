<script setup lang="ts">
/**
 * Approval panel.
 *
 * This DSH build has no external approval channel, so the panel's primary job is
 * to explain — in one sentence — what DSH is asking for and what the operator
 * should do on the PC. Approve/reject buttons only appear when the backend
 * reports that a decision can actually be delivered (`capability === true`): an
 * unavailable button that silently fails is worse than no button.
 */
import { computed, ref } from 'vue'
import { monitor } from '../stores/monitor.ts'
import { formatAgo, outcomeText, requiredActionLabel } from '../utils/format.ts'

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

/** First tap arms the button, second tap submits (only reachable when capable). */
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

/** Every pending request as one copyable list. */
const hintSummary = computed(() =>
  pending.value.map((request, index) => `${index + 1}. ${request.hint ?? request.reason ?? request.toolName}`).join('\n'),
)

/** Copy the summary for pasting into a chat with whoever runs DSH. */
function copyHints(): void {
  void navigator.clipboard?.writeText(hintSummary.value)
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
      <strong>手机只能查看，决定要在电脑上做。</strong>{{ capabilityReason }}
    </p>

    <p class="empty" v-if="pending.length === 0">
      当前没有待审批请求。出现审批时这里会自动更新（数据来自 DSH 会话日志里成对的
      <code>approval/asked</code> / <code>approval/decided</code> 事件）。
    </p>

    <ul class="list" v-else>
      <li class="request" v-for="request in pending" :key="request.id">
        <div class="request__head">
          <span class="request__tool">{{ request.toolName }}</span>
          <span class="request__badge" v-if="request.requiredAction">{{ requiredActionLabel(request.requiredAction) }}</span>
          <span class="request__time">{{ formatAgo(request.askedAt) }}</span>
        </div>

        <p class="request__hint" v-if="request.hint">{{ request.hint }}</p>
        <p class="request__raw" v-else-if="request.reason">原始请求原因：{{ request.reason }}</p>

        <dl class="request__facts">
          <div v-if="request.callId"><dt>工具调用</dt><dd class="mono">{{ request.callId.slice(0, 18) }}</dd></div>
          <div v-if="request.policy"><dt>当时策略</dt><dd>{{ request.policy }}</dd></div>
          <div><dt>请求 ID</dt><dd class="mono">{{ request.id.slice(0, 12) }}</dd></div>
          <div><dt>会话</dt><dd class="mono">{{ request.sessionId.slice(0, 22) }}</dd></div>
        </dl>

        <div class="request__actions" v-if="capability">
          <template v-if="confirming !== undefined && confirming.id === request.id">
            <p class="confirm">
              确认要对「{{ request.toolName }}」执行<strong>{{ confirming.action === 'approve' ? '批准' : '拒绝' }}</strong>吗？
            </p>
            <div class="actions-row">
              <button class="btn btn--danger" :disabled="busyId === request.id" @click="commit(request.id, confirming.action)">
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
        <p class="request__where" v-else>
          去运行 DSH 的那台电脑操作：Web GUI 的审批面板，或终端里的审批提示。处理后本页会自动更新。
        </p>
      </li>
    </ul>

    <div class="copyable" v-if="!capability && pending.length > 0">
      <div class="copyable__head">
        <span>提示汇总（可复制给别人或自己备忘）</span>
        <button class="copyable__btn" @click="copyHints">复制</button>
      </div>
      <pre class="copyable__body">{{ hintSummary }}</pre>
    </div>

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
  gap: 8px;
}

.request__tool {
  font-size: 15px;
  font-weight: 700;
}

.request__badge {
  font-size: 10px;
  padding: 2px 7px;
  border-radius: 999px;
  border: 1px solid var(--warn-line);
  background: var(--warn-bg);
  color: var(--warn);
  flex: 0 0 auto;
}

.request__hint {
  margin: 0;
  font-size: 13px;
  line-height: 1.65;
  color: var(--text);
  background: var(--field);
  border-radius: 10px;
  padding: 9px 10px;
}

.request__raw {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--muted);
  word-break: break-word;
}

.request__where {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--muted);
  border-top: 1px dashed var(--line);
  padding-top: 9px;
}

.copyable {
  border: 1px solid var(--line);
  background: var(--card);
  border-radius: 12px;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.copyable__head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  color: var(--muted);
}

.copyable__btn {
  border: 1px solid var(--line);
  background: var(--field);
  color: var(--text);
  border-radius: 999px;
  font-size: 11px;
  padding: 3px 10px;
}

.copyable__body {
  margin: 0;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
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

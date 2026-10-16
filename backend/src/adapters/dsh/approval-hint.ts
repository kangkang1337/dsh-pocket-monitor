/**
 * Turn a raw DSH approval request into one actionable sentence.
 *
 * Since this DSH build has no external approval channel, the phone cannot send a
 * decision back — so instead of a button that cannot work, the monitor explains
 * **what DSH is asking for** and **what the operator should do on the PC**. The
 * input is the same data DSH already writes into the session audit log
 * (`approval/asked`), so nothing here is guessed from anywhere else.
 *
 * @module dsh-pocket-monitor/adapters/dsh/approval-hint
 */

/** What kind of permission or decision the request represents. */
export type RequiredActionKind =
  | 'sandbox-escalation'
  | 'permission'
  | 'network-access'
  | 'file-access'
  | 'read-only-retry'
  | 'tool-permission'
  | 'approval-policy'

/** One derived, human-readable summary of a pending approval. */
export interface ApprovalHint {
  readonly kind: RequiredActionKind
  /** Short label for the kind of thing being authorised, e.g. `沙箱提权`. */
  readonly label: string
  /** The normalised target, e.g. `danger-full-access`. */
  readonly target?: string
  /** One actionable sentence for the phone. */
  readonly hint: string
}

/** Inputs the hint is derived from (all optional except the tool name). */
export interface ApprovalHintInput {
  readonly toolName: string
  readonly reason?: string
  readonly callId?: string
  /** Effective approval policy at the time of the request, when the log states it. */
  readonly policy?: string
  /** Session the request belongs to. */
  readonly sessionId?: string
}

/** Map a tool name to the Chinese label used inside the sentence. */
function toolLabel(toolName: string): string {
  switch (toolName) {
    case 'pwsh':
    case 'bash':
      return '执行命令行'
    case 'write':
    case 'edit':
    case 'str_replace':
      return '修改文件'
    case 'read':
      return '读取文件'
    case 'web_fetch':
      return '联网抓取网页'
    case 'web_search':
      return '联网搜索'
    case 'todo_board':
      return '读写待办板'
    case 'present':
      return '交付文件'
    case 'subagent':
      return '启动子代理'
    default:
      return toolName
  }
}

/**
 * Derive the one-liner shown on the phone.
 *
 * Recognised reasons (verified against real `approval/asked` events):
 * `escalate sandbox to <preset>: <why>`, permission/preset switches, network
 * needs, and the generic "no durable record of the outcome" retry case.
 *
 * @param input - the request as recorded by DSH.
 * @returns the kind, a short label, an optional target, and the sentence.
 */
export function describeApproval(input: ApprovalHintInput): ApprovalHint {
  const reason = input.reason?.trim() ?? ''
  const tool = input.toolName || 'unknown'
  const who = `「${toolLabel(tool)}」`

  const escalation = /escalate\s+sandbox\s+to\s+([A-Za-z0-9._-]+)\s*:?\s*(.*)$/i.exec(reason)
  if (escalation !== null) {
    const target = escalation[1] ?? ''
    const why = escalation[2]?.trim() ?? ''
    return {
      kind: 'sandbox-escalation',
      label: '沙箱提权',
      target,
      hint:
        `DSH 需要你的授权：把沙箱提升到 ${target}，以便${who}${why === '' ? '' : `（${why}）`}。` +
        `请在运行 DSH 的电脑上批准，手机端只能查看。`,
    }
  }

  const permission = /(?:grant|require|need|needs|request(?:ing)?)\s+permission\s+([A-Za-z0-9._:\- ]+)/i.exec(reason)
  if (permission !== null) {
    const target = permission[1]?.trim() ?? ''
    return {
      kind: 'permission',
      label: '权限申请',
      target,
      hint: `DSH 需要权限「${target}」才能继续${who}。请在运行 DSH 的电脑上批准，手机端只能查看。`,
    }
  }

  // Order matters: a concrete file path is the most specific fact in the reason,
  // so it wins over a generic "network" mention (a path can contain "hosts").
  const path = /([A-Za-z]:\\[^\s"']+|\/(?:home|etc|usr|var|opt|root|tmp)\/[A-Za-z0-9._\-\/]+)/.exec(reason)
  if (path !== null) {
    return {
      kind: 'file-access',
      label: '文件访问',
      target: path[1],
      hint: `DSH 需要访问文件 ${path[1]} 才能继续${who}。请在运行 DSH 的电脑上批准，手机端只能查看。`,
    }
  }

  if (/https?:\/\/|network\s+access|internet|proxy|\bdns\b|联网/i.test(reason)) {
    return {
      kind: 'network-access',
      label: '联网访问',
      hint: `DSH 需要联网访问才能继续${who}${reason === '' ? '' : `（${reason}）`}。请在运行 DSH 的电脑上批准，手机端只能查看。`,
    }
  }

  if (/outcome|unknown|idempotent|retry/i.test(reason)) {
    return {
      kind: 'read-only-retry',
      label: '需要重试确认',
      hint: `DSH 不确定上一次${who}的结果，需要你决定是否可以安全重试（只读或幂等的操作才建议直接重试）。请在运行 DSH 的电脑上处理，手机端只能查看。`,
    }
  }

  if (input.policy !== undefined && input.policy !== 'ask') {
    return {
      kind: 'approval-policy',
      label: '审批策略',
      target: input.policy,
      hint:
        `当前会话的审批策略是 ${input.policy}，所有需要审批的操作都会被自动拒绝。` +
        `如果确实要让${who}执行，请在运行 DSH 的电脑上改用 ask 策略或接受拒绝。`,
    }
  }

  return {
    kind: 'tool-permission',
    label: '工具授权',
    hint:
      `DSH 请求授权以${who}${reason === '' ? '' : `：${reason}`}。` +
      `请在运行 DSH 的电脑上批准或拒绝，手机端只能查看。`,
  }
}

/** Attach the derived hint fields to a pending-approval record. */
export function approvalHintFields(input: ApprovalHintInput): { requiredAction: RequiredActionKind; hint: string } {
  const described = describeApproval(input)
  return { requiredAction: described.kind, hint: described.hint }
}

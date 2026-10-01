import useSWR from 'swr'

// Mirrors the Go WAFResponse served by GET /api/waf (pkg/api/handler_waf.go). The dashboard
// reads live valkey state swarm-wide (the backing store is shared), so these numbers are the
// whole fleet, not one node.

export type WafBan = {
  ip: string
  source?: string
  ttl: number // seconds remaining
  expiresAt: number // unix millis
}

export type WafNode = {
  pass: number
  whitelist: number
  wouldBlock: number
  block: number
  scoped: number
  enqueue: number
  failOpen: number
  dropped: number
  blocklistSize: number
  whitelistSize: number
  lastRefresh?: number // unix millis
}

// WafConnHealth is the per-node (and aggregate) valkey link health, from the background-
// published heartbeat + cached circuit-breaker state (never a live ping).
export type WafConnHealth = {
  state: 'connected' | 'degraded' | 'down' | string
  breakerState: string // closed | open | half-open | unknown
  breakerOpenCount: number
  lastEnqueueOkMs?: number
  lastFlushOkMs?: number
  lastErrorMs?: number
  lastError?: string
  dropped: number
  heartbeatMs?: number
  stale: boolean
  endpoint?: string
}

// WafConfig echoes what the middleware is pointed at (never the password).
export type WafConfig = {
  endpoint: string
  streamKey: string
  streamMaxLen: number
  db: number
  authConfigured: boolean
  group: string
  dialTimeoutMs: number
  readTimeoutMs: number
  writeTimeoutMs: number
}

export type WafWorker = {
  group: string
  replicas: number
  pending: number
  lastConsumeMs: number
  heartbeatMs: number
  state: string // up | degraded | down
}

export type WafResponse = {
  degraded: boolean
  reason?: string
  timestamp: number
  mode: string // 'shadow' | 'enforce' | 'unknown'
  middleware?: string
  queue: { depth: number; pending: number; stream: string; group: string }
  bans: { active: number; recent: WafBan[] }
  lists: {
    blocklistSize: number
    whitelistSize: number
    blocklistKeys?: string[]
    whitelistKeys?: string[]
    lastRefresh?: number
  }
  nodes: Record<string, WafNode>
  totals: WafNode
  modsec: { available: boolean; healthy: boolean | null }
  config: WafConfig
  connection: Record<string, WafConnHealth>
  connectionAgg: WafConnHealth
  worker: WafWorker
}

// Poll interval for the live WAF view.
export const WAF_POLL_INTERVAL = 5000

const useWaf = (): { data?: WafResponse; error?: Error; isLoading: boolean } => {
  const { data, error, isLoading } = useSWR<WafResponse>('/waf', {
    refreshInterval: WAF_POLL_INTERVAL,
  })
  return { data, error, isLoading }
}

export default useWaf

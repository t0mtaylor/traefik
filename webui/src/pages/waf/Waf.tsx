import { Badge, Box, Card, Flex, Grid, H2, Text, Tooltip } from '@traefik-labs/faency'
import { ReactNode, useMemo } from 'react'

import useWaf, { WafBan, WafConfig, WafConnHealth, WafNode, WafResponse, WafWorker } from 'hooks/use-waf'
import PageTitle from 'layout/PageTitle'

const fmt = (n?: number): string => (typeof n === 'number' ? n.toLocaleString() : '—')

const ago = (ms?: number): string => {
  if (!ms) return 'never'
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`
  return `${Math.round(secs / 3600)}h ago`
}

// Responsive auto-fill grid: `min(100%, N)` guarantees a single column never exceeds the
// viewport, so the page has no horizontal scroll at phone width.
const autoGrid = (min: number): string => `repeat(auto-fill, minmax(min(100%, ${min}px), 1fr))`

// The seven per-node hot-path counters, in reading order, each with a plain-language
// description. These are CUMULATIVE HIT COUNTS since the traefik task started — NOT list sizes.
type CounterKey = 'pass' | 'enqueue' | 'dropped' | 'whitelist' | 'scoped' | 'block' | 'failOpen' | 'wouldBlock'

const COUNTERS: Array<{ key: CounterKey; label: string; desc: string; tone?: string }> = [
  { key: 'pass', label: 'pass', desc: 'Inspected and passed to the backend (in shadow every request passes).' },
  { key: 'enqueue', label: 'enqueue', desc: 'Queued to the worker for async modsec inspection.' },
  {
    key: 'dropped',
    label: 'dropped',
    desc: 'Inspection job dropped because the queue was full (valkey slow/down). The request still passed — this only skips out-of-band inspection, it never blocks or delays.',
    tone: 'orange',
  },
  {
    key: 'whitelist',
    label: 'whitelist',
    desc: 'Skipped — request came from a trusted CDN / owner / CGNAT CIDR. This is a HIT COUNT, not the size of the whitelist.',
  },
  { key: 'scoped', label: 'scoped', desc: 'Skipped — static / stream / health path, not inspected.' },
  { key: 'block', label: 'block', desc: 'Blocked. Enforce mode only — always 0 in shadow.', tone: 'red' },
  {
    key: 'failOpen',
    label: 'fail-open',
    desc: 'valkey / worker was unavailable, so the request was passed anyway (the WAF never blocks on error).',
    tone: 'orange',
  },
  {
    key: 'wouldBlock',
    label: 'would-block',
    desc: 'SHADOW preview: what enforce mode WOULD have blocked. Nothing is actually blocked in shadow.',
  },
]

const nodeValue = (node: WafNode, key: CounterKey): number => {
  switch (key) {
    case 'pass':
      return node.pass
    case 'enqueue':
      return node.enqueue
    case 'dropped':
      return node.dropped
    case 'whitelist':
      return node.whitelist
    case 'scoped':
      return node.scoped
    case 'block':
      return node.block
    case 'failOpen':
      return node.failOpen
    case 'wouldBlock':
      return node.wouldBlock
  }
}

const ModsecBadge = ({ modsec }: { modsec: WafResponse['modsec'] }) => {
  if (!modsec?.available) {
    return <Badge data-testid="waf-modsec-badge">modsec: n/a</Badge>
  }
  return (
    <Badge variant={modsec.healthy ? 'green' : 'red'} data-testid="waf-modsec-badge">
      modsec: {modsec.healthy ? 'up' : 'down'}
    </Badge>
  )
}

// ModeBanner is the prominent, unmistakable mode indicator the whole page hangs off of:
// SHADOW is amber/observe-only, ENFORCE is red/blocking. It answers "is it still shadow?" at a
// glance. Driven by the real mode from /api/waf.
const ModeBanner = ({ mode }: { mode: string }) => {
  const style =
    mode === 'enforce'
      ? { bg: '$red3', border: '1px solid $colors$red7', fg: '$red11', label: 'ENFORCE', sub: 'blocking active' }
      : mode === 'shadow'
        ? {
            bg: '$orange3',
            border: '1px solid $colors$orange7',
            fg: '$orange11',
            label: 'SHADOW',
            sub: 'observe-only · never blocks',
          }
        : {
            bg: '$grayBlue3',
            border: '1px solid $colors$grayBlue7',
            fg: '$grayBlue11',
            label: 'UNKNOWN',
            sub: 'mode not reported by /api/waf',
          }
  return (
    <Card
      data-testid="waf-mode-badge"
      css={{ p: '$3', backgroundColor: style.bg, border: style.border, width: '100%' }}
    >
      <Flex align="center" css={{ gap: '$3', flexWrap: 'wrap' }}>
        <Text css={{ fontSize: '$6', fontWeight: '$bold', letterSpacing: 1, color: style.fg }}>{style.label}</Text>
        <Text css={{ fontSize: '$3', color: style.fg }}>· {style.sub}</Text>
      </Flex>
    </Card>
  )
}

// Link-state palette: connected=green, degraded=amber, down=red. Drives the connection panel
// and the per-node status dots so valkey trouble is visible at a glance. Faency has no green
// token scale, so green is a raw hex (radix green9) while amber/red use the orange/red tokens;
// `badge` is a safe Faency Badge variant.
type LinkStyle = { badge: 'green' | 'orange' | 'red'; fg: string; bg: string; border: string; label: string }
const linkStyle = (state: string): LinkStyle => {
  switch (state) {
    case 'connected':
    case 'up':
      return { badge: 'green', fg: '$hiContrast', bg: 'transparent', border: '1px solid $colors$tableRowBorder', label: 'CONNECTED' }
    case 'degraded':
      return { badge: 'orange', fg: '$orange11', bg: '$orange3', border: '1px solid $colors$orange7', label: 'DEGRADED' }
    default:
      return { badge: 'red', fg: '$red11', bg: '$red3', border: '1px solid $colors$red7', label: 'DOWN' }
  }
}

const dotColor = (state: string): string =>
  state === 'connected' || state === 'up' ? '#30a46c' : state === 'degraded' ? '#f76b15' : '#e5484d'

// A small coloured dot for per-node link state.
const StatusDot = ({ state }: { state: string }) => (
  <Box css={{ width: 10, height: 10, borderRadius: '$round', backgroundColor: dotColor(state), flexShrink: 0 }} />
)

// ConnectionPanel is the prominent valkey link-health block: aggregate state banner + the
// breaker/heartbeat signals. All of it is from the cached heartbeat, never a live ping.
const ConnectionPanel = ({ agg, worker }: { agg?: WafConnHealth; worker?: WafWorker }) => {
  const state = agg?.state || 'down'
  const s = linkStyle(state)
  const breaker = agg?.breakerState || 'unknown'
  return (
    <Card css={{ p: '$3', backgroundColor: s.bg, border: s.border }} data-testid="waf-connection">
      <Flex direction="column" gap={3}>
        <Flex align="center" css={{ gap: '$2', flexWrap: 'wrap' }}>
          <StatusDot state={state} />
          <Text css={{ fontSize: '$4', fontWeight: '$bold', letterSpacing: 0.3, color: s.fg }}>valkey</Text>
          <Badge variant={s.badge}>{s.label}</Badge>
          <Badge variant={breaker === 'open' ? 'red' : breaker === 'half-open' ? 'orange' : 'green'}>
            breaker: {breaker}
          </Badge>
          {typeof agg?.breakerOpenCount === 'number' && agg.breakerOpenCount > 0 && (
            <Text css={{ color: s.fg, fontSize: '$2' }}>opened ×{fmt(agg.breakerOpenCount)}</Text>
          )}
        </Flex>
        <Grid css={{ gridTemplateColumns: autoGrid(150), gap: '$3' }}>
          <StatTile label="Last XADD ok" value={agg?.lastEnqueueOkMs ? ago(agg.lastEnqueueOkMs) : '—'} hint="enqueue heartbeat" />
          <StatTile label="Last flush ok" value={agg?.lastFlushOkMs ? ago(agg.lastFlushOkMs) : '—'} hint="stats flush heartbeat" />
          <StatTile label="Dropped" value={fmt(agg?.dropped)} hint="queue-full events" />
          <StatTile
            label="Worker"
            value={worker ? `${fmt(worker.replicas)} · ${worker.state}` : '—'}
            hint={worker ? `consume ${worker.lastConsumeMs ? ago(worker.lastConsumeMs) : 'never'}` : undefined}
          />
        </Grid>
        {agg?.lastError && (
          <Text css={{ color: s.fg, fontSize: '$1', fontFamily: 'monospace', wordBreak: 'break-word' }}>
            last error{agg.lastErrorMs ? ` (${ago(agg.lastErrorMs)})` : ''}: {agg.lastError}
          </Text>
        )}
      </Flex>
    </Card>
  )
}

// A plain key/value row for the configuration panel.
const ConfigRow = ({ k, v }: { k: string; v: ReactNode }) => (
  <Flex justify="between" css={{ gap: '$3', minWidth: 0 }}>
    <Text css={{ color: '$grayBlue9', fontSize: '$2', flexShrink: 0 }}>{k}</Text>
    <Text css={{ color: '$hiContrast', fontSize: '$2', fontFamily: 'monospace', wordBreak: 'break-all', textAlign: 'right' }}>
      {v}
    </Text>
  </Flex>
)

const ConfigPanel = ({ config, worker }: { config?: WafConfig; worker?: WafWorker }) => (
  <Card css={{ p: '$3' }} data-testid="waf-config">
    <Flex direction="column" gap={2}>
      <Text css={{ color: '$grayBlue9', fontSize: '$1', textTransform: 'uppercase', letterSpacing: 0.2 }}>
        Configuration
      </Text>
      <ConfigRow k="endpoint" v={config?.endpoint || '—'} />
      <ConfigRow k="stream" v={config?.streamKey || '—'} />
      <ConfigRow k="stream max len" v={fmt(config?.streamMaxLen)} />
      <ConfigRow k="db" v={typeof config?.db === 'number' ? config.db : '—'} />
      <ConfigRow k="auth" v={config?.authConfigured ? 'configured' : 'none'} />
      <ConfigRow
        k="timeouts (d/r/w)"
        v={config ? `${config.dialTimeoutMs}/${config.readTimeoutMs}/${config.writeTimeoutMs}ms` : '—'}
      />
      <ConfigRow k="worker group" v={worker?.group || config?.group || '—'} />
      <ConfigRow k="worker replicas" v={fmt(worker?.replicas)} />
      <ConfigRow k="worker lag" v={fmt(worker?.pending)} />
    </Flex>
  </Card>
)

const StatTile = ({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) => (
  <Card css={{ p: '$3', minWidth: 0 }}>
    <Flex direction="column" gap={1} css={{ minWidth: 0 }}>
      <Text css={{ color: '$grayBlue9', fontSize: '$1', textTransform: 'uppercase', letterSpacing: 0.2 }}>
        {label}
      </Text>
      <Text css={{ fontSize: '$6', fontWeight: '$semiBold', color: '$hiContrast', wordBreak: 'break-word' }}>
        {value}
      </Text>
      {hint && (
        <Text css={{ color: '$grayBlue9', fontSize: '$1', lineHeight: 1.4 }}>{hint}</Text>
      )}
    </Flex>
  </Card>
)

// Legend: a single, always-visible explanation of the seven counters so the page is
// self-explanatory even on touch devices where hover tooltips do not fire.
const CounterLegend = () => (
  <Card css={{ p: '$3' }} data-testid="waf-counter-legend">
    <Grid css={{ gridTemplateColumns: autoGrid(220), gap: '$2 $4' }}>
      {COUNTERS.map((c) => (
        <Flex key={c.key} css={{ gap: '$2', minWidth: 0 }}>
          <Text
            css={{
              fontFamily: 'monospace',
              fontWeight: '$semiBold',
              color: '$hiContrast',
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}
          >
            {c.label}
          </Text>
          <Text css={{ color: '$grayBlue9', fontSize: '$1', lineHeight: 1.4 }}>{c.desc}</Text>
        </Flex>
      ))}
    </Grid>
  </Card>
)

const Metric = ({ label, value, desc, tone }: { label: string; value: number; desc: string; tone?: string }) => {
  const toned = tone && value > 0
  return (
    <Tooltip content={desc} multiline>
      <Box as="span" css={{ display: 'flex', flexDirection: 'column', minWidth: 0, cursor: 'help' }}>
        <Text
          css={{
            color: '$grayBlue9',
            fontSize: '$1',
            borderBottom: '1px dotted $colors$grayBlue7',
            display: 'inline-block',
            width: 'fit-content',
          }}
        >
          {label}
        </Text>
        <Text css={{ fontWeight: '$semiBold', color: toned ? `$${tone}11` : '$hiContrast', whiteSpace: 'nowrap' }}>
          {fmt(value)}
        </Text>
      </Box>
    </Tooltip>
  )
}

const NodeTile = ({ name, node, conn }: { name: string; node: WafNode; conn?: WafConnHealth }) => (
  <Card css={{ p: '$3', minWidth: 0 }} data-testid={`waf-node-${name}`}>
    <Flex direction="column" gap={3} css={{ minWidth: 0 }}>
      <Flex align="center" justify="between" css={{ gap: '$2' }}>
        <Text css={{ fontWeight: '$semiBold', color: '$hiContrast' }}>{name}</Text>
        {conn && (
          <Tooltip content={`valkey ${conn.state}${conn.breakerState ? ` · breaker ${conn.breakerState}` : ''}`}>
            <Box as="span" css={{ display: 'flex', alignItems: 'center', gap: '$1', cursor: 'help' }}>
              <StatusDot state={conn.state} />
              <Text css={{ color: '$grayBlue9', fontSize: '$1' }}>{conn.state}</Text>
            </Box>
          </Tooltip>
        )}
      </Flex>
      <Grid css={{ gridTemplateColumns: autoGrid(72), gap: '$3 $2' }}>
        {COUNTERS.map((c) => (
          <Metric key={c.key} label={c.label} value={nodeValue(node, c.key)} desc={c.desc} tone={c.tone} />
        ))}
      </Grid>
      <Text css={{ color: '$grayBlue9', fontSize: '$1' }}>counters refreshed: {ago(node.lastRefresh)}</Text>
    </Flex>
  </Card>
)

const topCidrs = (bans: WafBan[]): Array<{ cidr: string; count: number }> => {
  const counts = new Map<string, number>()
  for (const b of bans) {
    let cidr = b.ip
    if (b.ip.includes('.') && !b.ip.includes(':')) {
      const parts = b.ip.split('.')
      if (parts.length === 4) cidr = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`
    }
    counts.set(cidr, (counts.get(cidr) || 0) + 1)
  }
  return Array.from(counts.entries())
    .map(([cidr, count]) => ({ cidr, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
}

export const WafView = ({ data }: { data: WafResponse }) => {
  const nodeNames = useMemo(() => Object.keys(data.nodes || {}).sort(), [data.nodes])
  const cidrs = useMemo(() => topCidrs(data.bans?.recent || []), [data.bans])

  const shadow = data.mode === 'shadow'
  const wlSize = data.lists?.whitelistSize
  const blSize = data.lists?.blocklistSize
  // Blocklist is legitimately empty in shadow (worker ban-feed not loaded) — say so rather than
  // leaving a bare, confusing "0".
  const blocklistValue = blSize === 0 && shadow ? '0' : `${fmt(blSize)} CIDRs`
  const blocklistHint = blSize === 0 && shadow ? 'not loaded in shadow' : 'blocklist trie (feeds + worker bans)'

  return (
    <Flex direction="column" gap={5} data-testid="waf page" css={{ width: '100%', maxWidth: '100%' }}>
      <Flex direction="column" gap={3}>
        <Flex align="center" css={{ gap: '$3', flexWrap: 'wrap' }}>
          <H2 css={{ fontSize: '$8', color: '$headingDefault' }}>WAF</H2>
          <ModsecBadge modsec={data.modsec} />
          {data.middleware && (
            <Text css={{ color: '$grayBlue9', fontSize: '$2', fontFamily: 'monospace' }}>{data.middleware}</Text>
          )}
        </Flex>
        <ModeBanner mode={data.mode} />
      </Flex>

      {data.degraded && (
        <Card
          css={{ p: '$3', backgroundColor: '$orange3', border: '1px solid $colors$orange7' }}
          data-testid="waf-degraded"
        >
          <Text css={{ color: '$orange11' }}>
            WAF data is degraded: {data.reason || 'valkey unreachable'}. Showing last-known / partial state.
          </Text>
        </Card>
      )}

      <Flex direction="column" gap={2}>
        <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Valkey connection &amp; configuration</H2>
        <Text css={{ color: '$grayBlue9', fontSize: '$2' }}>
          Link health from the background heartbeat + circuit-breaker state (no live ping). Stale or absent
          heartbeat ⇒ down; breaker open ⇒ degraded.
        </Text>
        <Grid css={{ gridTemplateColumns: autoGrid(320), gap: '$3' }}>
          <ConnectionPanel agg={data.connectionAgg} worker={data.worker} />
          <ConfigPanel config={data.config} worker={data.worker} />
        </Grid>
      </Flex>

      <Flex direction="column" gap={2}>
        <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Live queue &amp; lists</H2>
        <Text css={{ color: '$grayBlue9', fontSize: '$2' }}>
          Current valkey-backed state, shared across the whole fleet.
        </Text>
        <Grid css={{ gridTemplateColumns: autoGrid(170), gap: '$3' }}>
          <StatTile label="Queue depth" value={fmt(data.queue?.depth)} hint={`jobs waiting in ${data.queue?.stream || 'waf:stream'}`} />
          <StatTile label="Worker lag" value={fmt(data.queue?.pending)} hint={`pending / unacked in ${data.queue?.group || 'the consumer group'}`} />
          <StatTile label="Active bans" value={fmt(data.bans?.active)} hint="IPs currently banned" />
          <StatTile label="Whitelist" value={`${fmt(wlSize)} CIDRs`} hint="trusted CDN / owner / CGNAT trie" />
          <StatTile label="Blocklist" value={blocklistValue} hint={blocklistHint} />
          <StatTile label="List refresh" value={ago(data.lists?.lastRefresh)} hint="whitelist / blocklist trie last reloaded" />
        </Grid>
      </Flex>

      <Flex direction="column" gap={3}>
        <Flex direction="column" gap={1}>
          <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Requests (cumulative, since task restart)</H2>
          <Text css={{ color: '$grayBlue9', fontSize: '$2', lineHeight: 1.5 }}>
            Per-node hit counters since each traefik task last (re)started — <strong>not list sizes</strong>. Counts
            differ between nodes only because traffic volume differs; every node shares the same whitelist and
            blocklist tries. Hover a counter for its meaning.
          </Text>
        </Flex>
        <CounterLegend />
        {nodeNames.length === 0 ? (
          <Text css={{ color: '$grayBlue9' }} data-testid="waf-no-nodes">
            No per-node stats yet (middleware has not flushed counters).
          </Text>
        ) : (
          <Grid css={{ gridTemplateColumns: autoGrid(260), gap: '$3' }}>
            {nodeNames.map((name) => (
              <NodeTile key={name} name={name} node={data.nodes[name]} conn={data.connection?.[name]} />
            ))}
          </Grid>
        )}
      </Flex>

      <Grid css={{ gridTemplateColumns: autoGrid(300), gap: '$4' }}>
        <Flex direction="column" gap={2} css={{ minWidth: 0 }}>
          <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Recent bans</H2>
          <RecentBans bans={data.bans?.recent || []} />
        </Flex>
        <Flex direction="column" gap={2} css={{ minWidth: 0 }}>
          <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Top blocked CIDRs</H2>
          {cidrs.length === 0 ? (
            <Text css={{ color: '$grayBlue9' }}>No recent bans.</Text>
          ) : (
            <Card css={{ p: '$3' }}>
              <Flex direction="column" gap={2}>
                {cidrs.map((c) => (
                  <Flex key={c.cidr} justify="between" css={{ gap: '$2' }}>
                    <Text css={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{c.cidr}</Text>
                    <Badge variant="red">{c.count}</Badge>
                  </Flex>
                ))}
              </Flex>
            </Card>
          )}
        </Flex>
      </Grid>
    </Flex>
  )
}

const RecentBans = ({ bans }: { bans: WafBan[] }) => {
  if (bans.length === 0) {
    return (
      <Text css={{ color: '$grayBlue9' }} data-testid="waf-no-bans">
        No active bans.
      </Text>
    )
  }
  return (
    <Card css={{ p: 0, overflow: 'hidden' }}>
      <Box css={{ overflowX: 'auto' }}>
        <Box as="table" css={{ width: '100%', borderCollapse: 'collapse' }} data-testid="waf-bans-table">
          <Box as="thead">
            <Box as="tr" css={{ textAlign: 'left', borderBottom: '1px solid $colors$tableRowBorder' }}>
              <Th>IP</Th>
              <Th>Source</Th>
              <Th>TTL</Th>
            </Box>
          </Box>
          <Box as="tbody">
            {bans.map((b, i) => (
              <Box as="tr" key={`${b.ip}-${i}`} css={{ borderBottom: '1px solid $colors$tableRowBorder' }}>
                <Td mono>{b.ip}</Td>
                <Td>{b.source || '—'}</Td>
                <Td>{b.ttl > 0 ? `${b.ttl}s` : '—'}</Td>
              </Box>
            ))}
          </Box>
        </Box>
      </Box>
    </Card>
  )
}

const Th = ({ children }: { children: ReactNode }) => (
  <Box as="th" css={{ p: '$2 $3', color: '$grayBlue9', fontSize: '$1', fontWeight: '$semiBold' }}>
    {children}
  </Box>
)

const Td = ({ children, mono }: { children: ReactNode; mono?: boolean }) => (
  <Box as="td" css={{ p: '$2 $3', fontFamily: mono ? 'monospace' : undefined, color: '$hiContrast' }}>
    {children}
  </Box>
)

export const Waf = () => {
  const { data, error, isLoading } = useWaf()

  return (
    <Flex direction="column" gap={5}>
      <PageTitle title="WAF" />
      {error && !data ? (
        <Card css={{ p: '$3', backgroundColor: '$red3', border: '1px solid $colors$red7' }} data-testid="waf-error">
          <Text css={{ color: '$red11' }}>Failed to load WAF data: {String(error.message || error)}</Text>
        </Card>
      ) : !data ? (
        <Text css={{ color: '$grayBlue9' }} data-testid="waf-loading">
          {isLoading ? 'Loading WAF state…' : 'No WAF data.'}
        </Text>
      ) : (
        <WafView data={data} />
      )}
    </Flex>
  )
}

export default Waf

import { Badge, Box, Card, Flex, Grid, H2, Text } from '@traefik-labs/faency'
import { ReactNode, useMemo } from 'react'

import useWaf, { WafBan, WafNode, WafResponse } from 'hooks/use-waf'
import PageTitle from 'layout/PageTitle'

const fmt = (n?: number): string => (typeof n === 'number' ? n.toLocaleString() : '—')

const ago = (ms?: number): string => {
  if (!ms) return 'never'
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000))
  if (secs < 60) return `${secs}s ago`
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`
  return `${Math.round(secs / 3600)}h ago`
}

const ModeBadge = ({ mode }: { mode: string }) => {
  const variant = mode === 'enforce' ? 'red' : mode === 'shadow' ? 'blue' : undefined
  const label = mode === 'enforce' ? 'ENFORCE' : mode === 'shadow' ? 'SHADOW' : 'UNKNOWN'
  return (
    <Badge variant={variant} data-testid="waf-mode-badge">
      {label}
    </Badge>
  )
}

const ModsecBadge = ({ modsec }: { modsec: WafResponse['modsec'] }) => {
  if (!modsec?.available) {
    return (
      <Badge data-testid="waf-modsec-badge">modsec: n/a</Badge>
    )
  }
  return (
    <Badge variant={modsec.healthy ? 'green' : 'red'} data-testid="waf-modsec-badge">
      modsec: {modsec.healthy ? 'up' : 'down'}
    </Badge>
  )
}

const StatTile = ({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) => (
  <Card css={{ p: '$3' }}>
    <Flex direction="column" gap={1}>
      <Text css={{ color: '$grayBlue9', fontSize: '$1', textTransform: 'uppercase', letterSpacing: 0.2 }}>
        {label}
      </Text>
      <Text css={{ fontSize: '$7', fontWeight: '$semiBold', color: '$hiContrast' }}>{value}</Text>
      {hint && <Text css={{ color: '$grayBlue9', fontSize: '$1' }}>{hint}</Text>}
    </Flex>
  </Card>
)

const NodeTile = ({
  name,
  node,
  mode,
  modsec,
}: {
  name: string
  node: WafNode
  mode: string
  modsec: WafResponse['modsec']
}) => (
  <Card css={{ p: '$3' }} data-testid={`waf-node-${name}`}>
    <Flex direction="column" gap={2}>
      <Flex align="center" justify="between" css={{ gap: '$2' }}>
        <Text css={{ fontWeight: '$semiBold', color: '$hiContrast' }}>{name}</Text>
        <Flex css={{ gap: '$1' }}>
          <ModeBadge mode={mode} />
          <ModsecBadge modsec={modsec} />
        </Flex>
      </Flex>
      <Grid css={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: '$2', mt: '$1' }}>
        <Metric label="pass" value={node.pass} />
        <Metric label="block" value={node.block} tone={node.block ? 'red' : undefined} />
        <Metric label="enqueue" value={node.enqueue} />
        <Metric label="whitelist" value={node.whitelist} />
        <Metric label="scoped" value={node.scoped} />
        <Metric label="fail-open" value={node.failOpen} tone={node.failOpen ? 'orange' : undefined} />
      </Grid>
      <Flex justify="between" css={{ mt: '$2' }}>
        <Text css={{ color: '$grayBlue9', fontSize: '$1' }}>
          would-block: {fmt(node.wouldBlock)}
        </Text>
        <Text css={{ color: '$grayBlue9', fontSize: '$1' }}>refresh: {ago(node.lastRefresh)}</Text>
      </Flex>
    </Flex>
  </Card>
)

const Metric = ({ label, value, tone }: { label: string; value: number; tone?: string }) => (
  <Flex direction="column">
    <Text css={{ color: '$grayBlue9', fontSize: '$1' }}>{label}</Text>
    <Text css={{ fontWeight: '$semiBold', color: tone ? `$${tone}11` : '$hiContrast' }}>{fmt(value)}</Text>
  </Flex>
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

  return (
    <Flex direction="column" gap={5} data-testid="waf page">
      <Flex align="center" gap={3}>
        <H2 css={{ fontSize: '$8', color: '$headingDefault' }}>WAF</H2>
        <ModeBadge mode={data.mode} />
        <ModsecBadge modsec={data.modsec} />
        {data.middleware && (
          <Text css={{ color: '$grayBlue9', fontSize: '$2' }}>{data.middleware}</Text>
        )}
      </Flex>

      {data.degraded && (
        <Card css={{ p: '$3', backgroundColor: '$orange3', border: '1px solid $colors$orange7' }} data-testid="waf-degraded">
          <Text css={{ color: '$orange11' }}>
            WAF data is degraded: {data.reason || 'valkey unreachable'}. Showing last-known / partial state.
          </Text>
        </Card>
      )}

      <Grid css={{ gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: '$3' }}>
        <StatTile label="Queue depth" value={fmt(data.queue?.depth)} hint={data.queue?.stream} />
        <StatTile label="Worker lag" value={fmt(data.queue?.pending)} hint={data.queue?.group} />
        <StatTile label="Active bans" value={fmt(data.bans?.active)} />
        <StatTile label="Blocklist" value={fmt(data.lists?.blocklistSize)} hint="CIDRs" />
        <StatTile label="Whitelist" value={fmt(data.lists?.whitelistSize)} hint="CIDRs" />
        <StatTile label="List refresh" value={ago(data.lists?.lastRefresh)} />
      </Grid>

      <Flex direction="column" gap={3}>
        <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Nodes</H2>
        {nodeNames.length === 0 ? (
          <Text css={{ color: '$grayBlue9' }} data-testid="waf-no-nodes">
            No per-node stats yet (middleware has not flushed counters).
          </Text>
        ) : (
          <Grid css={{ gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '$3' }}>
            {nodeNames.map((name) => (
              <NodeTile key={name} name={name} node={data.nodes[name]} mode={data.mode} modsec={data.modsec} />
            ))}
          </Grid>
        )}
      </Flex>

      <Grid css={{ gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '$4' }}>
        <Flex direction="column" gap={2}>
          <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Recent bans</H2>
          <RecentBans bans={data.bans?.recent || []} />
        </Flex>
        <Flex direction="column" gap={2}>
          <H2 css={{ fontSize: '$5', color: '$headingDefault' }}>Top blocked CIDRs</H2>
          {cidrs.length === 0 ? (
            <Text css={{ color: '$grayBlue9' }}>No recent bans.</Text>
          ) : (
            <Card css={{ p: '$3' }}>
              <Flex direction="column" gap={2}>
                {cidrs.map((c) => (
                  <Flex key={c.cidr} justify="between">
                    <Text css={{ fontFamily: 'monospace' }}>{c.cidr}</Text>
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

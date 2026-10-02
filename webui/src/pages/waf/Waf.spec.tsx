import useWaf from 'hooks/use-waf'
import type { WafResponse } from 'hooks/use-waf'
import { Waf } from 'pages/waf/Waf'
import { renderWithProviders } from 'utils/test'

// Mock only the data hook so the render tests don't touch the network or SWR internals; the
// real SWRConfig provider in renderWithProviders is left intact.
vi.mock('hooks/use-waf', () => ({ __esModule: true, default: vi.fn(), WAF_POLL_INTERVAL: 5000 }))

const sample: WafResponse = {
  degraded: false,
  timestamp: Date.now(),
  mode: 'shadow',
  middleware: 'waf@file',
  queue: { depth: 7, pending: 3, stream: 'waf:stream', group: 'waf-workers' },
  bans: {
    active: 12,
    recent: [{ ip: '1.2.3.4', source: 'modsec 403', ttl: 3400, expiresAt: Date.now() + 3400000 }],
  },
  lists: { blocklistSize: 336000, whitelistSize: 233, lastRefresh: Date.now() - 20000 },
  nodes: {
    mx01: {
      pass: 100,
      whitelist: 3,
      wouldBlock: 2,
      block: 5,
      scoped: 40,
      enqueue: 90,
      failOpen: 1,
      dropped: 0,
      blocklistSize: 336000,
      whitelistSize: 233,
      lastRefresh: Date.now() - 20000,
    },
  },
  totals: {
    pass: 100,
    whitelist: 3,
    wouldBlock: 2,
    block: 5,
    scoped: 40,
    enqueue: 90,
    failOpen: 1,
    dropped: 0,
    blocklistSize: 0,
    whitelistSize: 0,
  },
  modsec: { available: true, healthy: true, state: 'up', lastCheckMs: Date.now() - 1200, url: 'http://10.106.0.2:8091', lastError: '' },
  config: {
    endpoint: 'ttdf-valkey-master:6379',
    streamKey: 'waf:stream',
    streamMaxLen: 1000000,
    db: 0,
    authConfigured: true,
    group: 'waf-workers',
    dialTimeoutMs: 50,
    readTimeoutMs: 50,
    writeTimeoutMs: 50,
  },
  connection: {
    mx01: {
      state: 'connected',
      breakerState: 'closed',
      breakerOpenCount: 0,
      lastEnqueueOkMs: Date.now() - 1000,
      lastFlushOkMs: Date.now() - 2000,
      dropped: 0,
      heartbeatMs: Date.now() - 1000,
      stale: false,
    },
  },
  connectionAgg: {
    state: 'connected',
    breakerState: 'closed',
    breakerOpenCount: 0,
    lastEnqueueOkMs: Date.now() - 1000,
    lastFlushOkMs: Date.now() - 2000,
    dropped: 0,
    heartbeatMs: Date.now() - 1000,
    stale: false,
  },
  worker: {
    group: 'waf-workers',
    replicas: 1,
    pending: 3,
    lastConsumeMs: Date.now() - 1500,
    heartbeatMs: Date.now() - 1000,
    state: 'up',
    processed1h: 1200,
    processed24h: 28000,
  },
}

afterEach(() => vi.clearAllMocks())

describe('<Waf />', () => {
  it('renders the per-node tile, summary tiles and recent bans', () => {
    vi.mocked(useWaf).mockReturnValue({ data: sample, error: undefined, isLoading: false })

    const { getByTestId, getAllByTestId, getByText } = renderWithProviders(<Waf />)

    expect(getByTestId('waf page')).toBeInTheDocument()
    // Mode badge is the prominent banner at the top.
    expect(getAllByTestId('waf-mode-badge')[0]).toHaveTextContent('SHADOW')
    expect(getByTestId('waf-node-mx01')).toBeInTheDocument()
    expect(getByTestId('waf-bans-table')).toBeInTheDocument()
    expect(getByText('1.2.3.4')).toBeInTheDocument()
  })

  it('makes the shadow mode unmistakable and explains the counters', () => {
    vi.mocked(useWaf).mockReturnValue({ data: sample, error: undefined, isLoading: false })

    const { getByTestId, getByText } = renderWithProviders(<Waf />)
    // The mode banner spells out that shadow never blocks.
    expect(getByTestId('waf-mode-badge')).toHaveTextContent('observe-only')
    // The always-visible legend explains the counters so the page is self-explanatory.
    expect(getByTestId('waf-counter-legend')).toBeInTheDocument()
    // The "requests are cumulative hit counters, not list sizes" clarification is present.
    expect(getByText(/cumulative, since task restart/i)).toBeInTheDocument()
  })

  it('shows the valkey connection panel and configuration', () => {
    vi.mocked(useWaf).mockReturnValue({ data: sample, error: undefined, isLoading: false })

    const { getByTestId, getAllByText } = renderWithProviders(<Waf />)
    expect(getByTestId('waf-connection')).toHaveTextContent('CONNECTED')
    expect(getByTestId('waf-connection')).toHaveTextContent('breaker: closed')
    const config = getByTestId('waf-config')
    expect(config).toHaveTextContent('ttdf-valkey-master:6379')
    expect(config).toHaveTextContent('50/50/50ms')
    expect(config).toHaveTextContent('configured')
    // endpoint appears in both connection endpoint context and config.
    expect(getAllByText(/waf:stream/i).length).toBeGreaterThan(0)
  })

  it('shows a real last-write timestamp when connected even if hot-path enqueue is 0', () => {
    vi.mocked(useWaf).mockReturnValue({
      data: {
        ...sample,
        // No hot-path enqueue stamp, but the stats/health flush is recent — must NOT show "—".
        connectionAgg: { ...sample.connectionAgg, lastEnqueueOkMs: 0, lastFlushOkMs: Date.now() - 3000 },
      },
      error: undefined,
      isLoading: false,
    })
    const panel = renderWithProviders(<Waf />).getByTestId('waf-connection')
    expect(panel).toHaveTextContent(/Last valkey write/i)
    expect(panel).not.toHaveTextContent('Last valkey write—')
    expect(panel).toHaveTextContent(/ago/i)
  })

  it('shows the modsec link health and worker throughput', () => {
    vi.mocked(useWaf).mockReturnValue({ data: sample, error: undefined, isLoading: false })
    const { getByTestId, getByText } = renderWithProviders(<Waf />)
    // modsec link in the connection panel.
    expect(getByTestId('waf-modsec-link')).toHaveTextContent('modsec')
    expect(getByTestId('waf-modsec-link')).toHaveTextContent('up')
    // modsec header badge reflects state.
    expect(getByTestId('waf-modsec-badge')).toHaveTextContent('modsec: up')
    // throughput is shown (processed last 1h / 24h).
    expect(getByText(/1,200 \/ 1h/)).toBeInTheDocument()
    expect(getByText(/28,000 processed in the last 24h/)).toBeInTheDocument()
  })

  it('labels stream length as retained (not a backlog) and worker lag as the real backlog', () => {
    vi.mocked(useWaf).mockReturnValue({ data: sample, error: undefined, isLoading: false })
    const { getByText, getAllByText } = renderWithProviders(<Waf />)
    expect(getByText(/Worker lag \(backlog\)/i)).toBeInTheDocument()
    // "the REAL backlog" appears in both the section caption and the tile hint.
    expect(getAllByText(/the REAL backlog/i).length).toBeGreaterThan(0)
    expect(getByText(/total events retained/i)).toBeInTheDocument()
    expect(getByText(/NOT a backlog/i)).toBeInTheDocument()
  })

  it('renders the degraded (breaker open) and down connection states', () => {
    vi.mocked(useWaf).mockReturnValue({
      data: {
        ...sample,
        connectionAgg: { ...sample.connectionAgg, state: 'degraded', breakerState: 'open', breakerOpenCount: 4, lastError: 'dial tcp i/o timeout', lastErrorMs: Date.now() - 500 },
      },
      error: undefined,
      isLoading: false,
    })
    const { getByTestId, rerender } = renderWithProviders(<Waf />)
    expect(getByTestId('waf-connection')).toHaveTextContent('DEGRADED')
    expect(getByTestId('waf-connection')).toHaveTextContent('dial tcp i/o timeout')

    vi.mocked(useWaf).mockReturnValue({
      data: { ...sample, connectionAgg: { ...sample.connectionAgg, state: 'down' }, worker: { ...sample.worker, state: 'down', replicas: 0 } },
      error: undefined,
      isLoading: false,
    })
    rerender(<Waf />)
    expect(getByTestId('waf-connection')).toHaveTextContent('DOWN')
  })

  it('labels an empty blocklist in shadow instead of a bare 0', () => {
    vi.mocked(useWaf).mockReturnValue({
      data: { ...sample, lists: { ...sample.lists, blocklistSize: 0 } },
      error: undefined,
      isLoading: false,
    })

    const { getByText } = renderWithProviders(<Waf />)
    expect(getByText('not loaded in shadow')).toBeInTheDocument()
  })

  it('handles degraded:true gracefully', () => {
    vi.mocked(useWaf).mockReturnValue({
      data: { ...sample, degraded: true, reason: 'valkey unreachable' },
      error: undefined,
      isLoading: false,
    })

    const { getByTestId } = renderWithProviders(<Waf />)
    expect(getByTestId('waf-degraded')).toBeInTheDocument()
    // The rest of the page still renders.
    expect(getByTestId('waf page')).toBeInTheDocument()
  })

  it('shows a loading state before data arrives', () => {
    vi.mocked(useWaf).mockReturnValue({ data: undefined, error: undefined, isLoading: true })

    const { getByTestId } = renderWithProviders(<Waf />)
    expect(getByTestId('waf-loading')).toBeInTheDocument()
  })
})

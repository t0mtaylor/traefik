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
  modsec: { available: false, healthy: null },
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

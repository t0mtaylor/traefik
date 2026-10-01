import { renderHook } from '@testing-library/react'
import useSWR from 'swr'

import useWaf, { WAF_POLL_INTERVAL } from 'hooks/use-waf'

// This spec exercises the real hook, so it mocks SWR itself (no component tree / provider is
// rendered here, so mocking the whole swr module is safe).
vi.mock('swr')

describe('useWaf', () => {
  afterEach(() => vi.clearAllMocks())

  it('fetches /waf (→ /api/waf) and polls on the WAF interval', () => {
    vi.mocked(useSWR).mockReturnValue({ data: undefined, error: undefined, isLoading: true } as never)

    renderHook(() => useWaf())

    expect(useSWR).toHaveBeenCalledWith('/waf', { refreshInterval: WAF_POLL_INTERVAL })
    expect(WAF_POLL_INTERVAL).toBe(5000)
  })

  it('passes through SWR data', () => {
    const data = { degraded: false } as never
    vi.mocked(useSWR).mockReturnValue({ data, error: undefined, isLoading: false } as never)

    const { result } = renderHook(() => useWaf())
    expect(result.current.data).toBe(data)
    expect(result.current.isLoading).toBe(false)
  })
})

// Per-IP investigation — one source address's whole profile: summary
// chips, tabbed Activity/Indicators/Correlation views (ips.html's
// attacker-profile layout, #1682), and the newest events with the record
// inspector.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { Tabs, TabPanel } from '../components/Tabs'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

type Kv = { key: string; count: number }
type Technique = { id: string; name: string; domain: string; evidence: string; count: number; url: string }

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  record: JsonRecord
}

type Correlation = {
  total: number
  truncated: boolean
  sensors: Kv[]
  tunnel_connections: number
  tunnel_os_guesses: string[]
  records: EventRow[]
}

type IpProfile = {
  ip: string
  total: number
  first: string
  last: string
  country: string
  asn: string
  sensors: Kv[]
  ports: Kv[]
  protos: Kv[]
  credentials: Kv[]
  commands: Kv[]
  sessions: Kv[]
  techniques: Technique[]
  /** #1689: this address was both carried by an analysed sample (floss
   * decoded a reference to it) and reached by a sandbox detonation of that
   * same sample. Advisory context only — the manual block action is
   * deliberately not gated on it. */
  confirmed_malicious: boolean
  payloads: Kv[]
  alerts: Kv[]
  fingerprints: Kv[]
  paths: Kv[]
  events: EventRow[]
  correlation: Correlation
}

type BlockState = { IP: string; Blocked: boolean; Active: boolean; BlockedBy?: string; ExpiresAt?: string }

// #2178: serviceJSON collapsed "the request failed" into the same null the
// route read as "No events from this address" — on the page an operator
// consults before deciding whether to keep or lift a block, an outage
// asserting a whole address's history was empty. Tri-state now; the
// handler never rejects.
type ProfileFetch = { state: 'profile'; profile: IpProfile } | { state: 'missing' } | { state: 'failed' }

const fetchProfile = createServerFn({ method: 'GET' })
  .validator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<ProfileFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<IpProfile>(`/api/v1/investigate/ip/${encodeURIComponent(data.ip)}`)
    if (result.ok) return { state: 'profile', profile: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

const fetchBlockState = createServerFn({ method: 'GET' })
  .validator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<BlockState | null> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/ip-block/${encodeURIComponent(data.ip)}`)
    return response.ok ? ((await response.json()) as BlockState) : null
  })

const setBlock = createServerFn({ method: 'POST' })
  // expires_days is required on a block (#3525): 0 = permanent.
  .validator((input: { ip: string; blocked: boolean; expires_days?: number }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF, same posture as the legacy action (#914).
    if (!user || user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ip-block', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, actor: user?.username ?? '' }),
    })
    return response.ok
  })

function BlockControl({ ip }: { ip: string }) {
  const [state, setState] = useState<BlockState | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let cancelled = false
    fetchBlockState({ data: { ip } }).then((result) => {
      if (!cancelled) setState(result)
    })
    return () => {
      cancelled = true
    }
  }, [ip])
  const apply = async (blocked: boolean, expiresDays?: number) => {
    setBusy(true)
    try {
      const ok = await setBlock({ data: { ip, blocked, ...(expiresDays === undefined ? {} : { expires_days: expiresDays }) } })
      if (ok) {
        const fresh = await fetchBlockState({ data: { ip } })
        if (fresh) setState(fresh)
      }
    } finally {
      setBusy(false)
    }
  }
  if (state === null) return null
  // ips.html:101-102. The port collapsed both states into one `chip
  // is-active` toggle — a class theme.css has no rule for, so blocking an
  // address looked identical to any other inert chip, and the expiry input
  // was dropped outright. That second part was not cosmetic: the whole
  // pipeline behind it survived the port (the server fn validator accepts
  // expires_days and spreads it straight through to ip_block.rs), so with
  // no control to set it every block placed through this UI was permanent.
  // The select below restores it, and the backend now requires it (#3525).
  if (state.Active) {
    return (
      <span className="hp-row">
        <span className="chip badge badge--danger">
          blocked{state.BlockedBy ? ` by ${state.BlockedBy}` : ''}
          {state.ExpiresAt ? `, expires ${formatTimestamp(state.ExpiresAt)}` : ''}
        </span>
        <button
          className="btn btn-sm btn-secondary"
          type="button"
          disabled={busy}
          title="Remove this IP from the manual blackhole list."
          onClick={() => void apply(false)}
        >
          {busy ? '…' : 'unblock'}
        </button>
      </span>
    )
  }
  return (
    <form
      className="inline-form hp-row"
      onSubmit={(event) => {
        event.preventDefault()
        const raw = new FormData(event.currentTarget).get('expires_days')
        const days = Number(raw)
        // 0 = permanent; never fall back to an absent duration (#3525).
        void apply(true, Number.isInteger(days) && days >= 0 ? days : 7)
      }}
    >
      <label htmlFor="attacker-block-expires">block for</label>
      <select id="attacker-block-expires" name="expires_days" className="form-input" defaultValue="7">
        <option value="1">1 day</option>
        <option value="7">7 days</option>
        <option value="30">30 days</option>
        <option value="0">permanent</option>
      </select>
      <button
        className="btn btn-sm btn-danger"
        type="submit"
        disabled={busy}
        title="Drop this IP's connections at portbridge going forward; does not retroactively affect anything already logged"
      >
        {busy ? '…' : 'block'}
      </button>
    </form>
  )
}

export const Route = createFileRoute('/investigate/ip/$ip')({
  loader: async ({ params }) => ({ first: fetchProfile({ data: { ip: params.ip } }) }),
  component: InvestigateIp,
})

const EVENT_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
  { header: 'port', className: 'n', render: (row) => (row.port ? `:${row.port}` : '') },
  { header: 'detail', className: 'v', render: (row) => row.detail || row.proto },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

function MiniTable({ title, rows, linkTo }: { title: string; rows: Kv[]; linkTo?: (key: string) => string }) {
  if (rows.length === 0) return null
  return (
    <div className="card half">
      <h2>{title}</h2>
      <div className="card__scroll">
        <table className="data-table">
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td className="n">{row.count.toLocaleString('en-US')}</td>
                <td className="v">{linkTo ? <a href={linkTo(row.key)}>{row.key}</a> : row.key}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function TechniquesTable({ techniques }: { techniques: Technique[] }) {
  if (techniques.length === 0) return null
  return (
    <div className="card wide">
      <h2>MITRE ATT&amp;CK behavior mapping</h2>
      <p className="note">Evidence-based behavioral context only; this does not identify or attribute an actor.</p>
      <div className="card__scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>domain</th>
              <th>technique</th>
              <th>observations</th>
              <th>evidence</th>
            </tr>
          </thead>
          <tbody>
            {techniques.map((technique) => (
              <tr key={technique.id}>
                <td>
                  <span className="badge badge--muted">{technique.domain}</span>
                </td>
                <td className="v">
                  <a href={technique.url} target="_blank" rel="noopener noreferrer">
                    {technique.id} — {technique.name}
                  </a>
                </td>
                <td className="n">{technique.count.toLocaleString('en-US')}</td>
                <td className="v">{technique.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

const CORRELATION_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
  { header: 'summary', className: 'v', render: (row) => row.detail || row.proto },
]

function CorrelationPanel({ correlation }: { correlation: Correlation }) {
  return (
    <>
      <div className="metric-grid">
        <div className="metric">
          <div className="metric__value">{correlation.total.toLocaleString('en-US')}</div>
          <div className="metric__label">Total ES matches</div>
        </div>
        <div className="metric">
          <div className="metric__value">{correlation.tunnel_connections.toLocaleString('en-US')}</div>
          <div className="metric__label">Tunnel connections</div>
        </div>
        <div className="metric">
          <div className="metric__value">{correlation.sensors.length}</div>
          <div className="metric__label">Distinct sensors</div>
        </div>
      </div>
      <div className="card wide">
        <h2>Elasticsearch correlation</h2>
        <p className="note">
          Everything the backend has seen for this IP across honeypot, Suricata, and portbridge tunnel records — not
          limited to the in-memory window above.
          {correlation.truncated
            ? ` Showing the ${correlation.records.length.toLocaleString('en-US')} most recent of ${correlation.total.toLocaleString('en-US')} total matches.`
            : ''}
        </p>
        {correlation.tunnel_os_guesses.length > 0 ? (
          <p>
            <strong>p0f OS guesses seen over this tunnel:</strong> {correlation.tunnel_os_guesses.join(', ')}
          </p>
        ) : null}
        {correlation.records.length > 0 ? (
          <div className="card__scroll">
            <table className="recent data-table">
              <thead>
                <tr>
                  <th>time</th>
                  <th>sensor</th>
                  <th>summary</th>
                </tr>
              </thead>
              <tbody>
                {correlation.records.map((record, index) => (
                  <tr key={`${record.time}-${index}`}>
                    <td>{formatTimestamp(record.time)}</td>
                    <td>{record.sensor}</td>
                    <td className="v">{record.detail || record.proto}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="empty">No Elasticsearch correlation records were found for this IP.</p>
        )}
      </div>
      <div className="card wide">
        <h2>Attack progression</h2>
        <p className="note">Chronological, oldest to newest; capped to the latest 250 matching records.</p>
        <MasterDetailTable
          rows={[...correlation.records].reverse()}
          columns={CORRELATION_COLUMNS}
          rowKey={(row, index) => `progression-${row.time}-${index}`}
          emptyState={{
            title: 'No Elasticsearch correlation records were found for this IP',
            hint: 'This address has been seen, but nothing correlatable has been indexed for it yet.',
          }}
          inspectorTitle="Event record"
        />
      </div>
    </>
  )
}

function InvestigateIp() {
  const { first } = Route.useLoaderData()
  const { ip } = Route.useParams()
  // #2178: `result ?? 'missing'` rendered a failed profile fetch as "No
  // events from this address in the current window." — a confident
  // negative about everything this IP ever did. Tri-state now: null while
  // loading, 'missing' only for a settled not-found, 'failed' named.
  const [fetch, setFetch] = useState<ProfileFetch | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [tab, setTab] = useState('activity')
  useEffect(() => {
    let cancelled = false
    setFetch(null)
    ;(attempt === 0 ? first : fetchProfile({ data: { ip } })).then((result) => {
      if (!cancelled) setFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])

  if (fetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader label="Investigate" title={ip} subtitle="The profile could not be loaded." />
        <ErrorStateBlock
          title="This attacker profile failed to load"
          hint="The backend request failed — this says nothing about whether the address has history. Do not treat it as an empty profile."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }

  if (fetch?.state === 'missing') {
    return (
      <InvestigateHeader label="Investigate" title={ip} subtitle="No events from this address in the current window." />
    )
  }

  const profile = fetch?.state === 'profile' ? fetch.profile : null

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title={ip}
        subtitle="Everything this source address did across every sensor — behavior, credentials, sessions and raw events."
        chips={
          profile ? (
            <>
              <span className="chip">{profile.total.toLocaleString('en-US')} events</span>
              {/* #1689: only rendered when true. An absent badge means "no
                  such corroboration", not "benign" — most addresses here are
                  hostile and simply never appeared in an analysed sample. */}
              {profile.confirmed_malicious ? (
                <span
                  className="badge badge--danger"
                  title="A sandbox detonation of a sample that references this address actually connected to it — two independent pipelines agree. Informational: the block action is not gated on this."
                >
                  confirmed malicious (sandbox)
                </span>
              ) : null}
              {profile.country ? <span className="badge badge--info" title={countryName(profile.country)}>{profile.country}</span> : null}
              {profile.asn ? <span className="chip">{profile.asn}</span> : null}
              <span className="chip">
                {formatTimestamp(profile.first)} → {formatTimestamp(profile.last)}
              </span>
              <Link className="chip" to="/events" search={{ ip }}>
                all matching events →
              </Link>
              <Link className="chip" to="/recordings" search={{ ip }} title="TTY session recordings from this IP, if any">
                session recordings
              </Link>
              <a className="chip" href={`/api/export/events.csv?ip=${encodeURIComponent(ip)}`}>
                export CSV ↓
              </a>
              <BlockControl ip={ip} />
            </>
          ) : undefined
        }
      />
      {profile ? (
        <>
          <Tabs
            tabs={[
              { id: 'activity', label: 'Activity' },
              { id: 'indicators', label: 'Indicators' },
              { id: 'correlation', label: 'Correlation & timeline' },
            ]}
            active={tab}
            onSelect={setTab}
            label="Attacker profile views"
            idPrefix="attacker-profile"
          />
          <TabPanel id="activity" active={tab} idPrefix="attacker-profile" className="dashboard-panel">
            <div className="">
              <MiniTable title="Sensors contacted" rows={profile.sensors} />
              <MiniTable title="Credentials attempted" rows={profile.credentials} />
              <MiniTable title="Commands" rows={profile.commands} />
              <MiniTable title="HTTP paths" rows={profile.paths} />
              <MiniTable title="Targeted ports" rows={profile.ports} />
              <MiniTable title="Protocols" rows={profile.protos} />
              <MiniTable title="Sessions" rows={profile.sessions} linkTo={(key) => `/sessions/${encodeURIComponent(key)}`} />
            </div>
          </TabPanel>
          <TabPanel id="indicators" active={tab} idPrefix="attacker-profile" className="dashboard-panel">
            <div className="">
              <MiniTable title="Payload hashes" rows={profile.payloads} linkTo={(key) => `/payload-analysis/${encodeURIComponent(key)}`} />
              <MiniTable title="Alerts" rows={profile.alerts} />
              <MiniTable title="Fingerprints" rows={profile.fingerprints} />
            </div>
            <TechniquesTable techniques={profile.techniques} />
          </TabPanel>
          <TabPanel id="correlation" active={tab} idPrefix="attacker-profile" className="dashboard-panel">
            <CorrelationPanel correlation={profile.correlation} />
          </TabPanel>
        </>
      ) : (
        <MasterDetailTable rows={null} columns={EVENT_COLUMNS} rowKey={(row, index) => `${row.time}-${index}`} inspectorTitle="Event record" />
      )}
    </>
  )
}

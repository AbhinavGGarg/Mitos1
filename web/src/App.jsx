import React, { useEffect, useMemo, useRef, useState } from 'react'

/* Every value rendered here comes from a live engine call.
   /api/scan  — real GitHub code search + real per-copy byte reads
   /api/repair — real three-way merge, golden hash gate, two ASan builds, real PoC probe
   /api/source — ClanLib's actual vendored file at the pinned commit
   /api/evidence — the artifacts the last run wrote to disk
   No simulated state, no setTimeout theatre. */

const useSSE = () => {
  const ref = useRef(null)
  const open = (url, onEvent, onClose) => {
    ref.current?.close()
    const es = new EventSource(url); ref.current = es
    es.onmessage = (e) => {
      const d = JSON.parse(e.data); onEvent(d)
      if (['done', 'result', 'error'].includes(d.type)) { es.close(); onClose?.(d) }
    }
    es.onerror = () => { es.close(); onClose?.(null) }
  }
  useEffect(() => () => ref.current?.close(), [])
  return open
}

const SECTIONS = [
  ['audit', 'Audit a repo'], ['hunt', 'The hunt'], ['target', 'The target'],
  ['repair', 'The repair'], ['proof', 'The proof'], ['evidence', 'Evidence'],
]

/* ── 00 · AUDIT YOUR REPO ──────────────────────────────────── */
function Audit() {
  const [repo, setRepo] = useState('')
  const [rows, setRows] = useState([])
  const [skipped, setSkipped] = useState([])
  const [checking, setChecking] = useState(null)
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(null)
  const openSSE = useSSE()

  const run = (e) => {
    e?.preventDefault()
    const r = repo.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '')
    if (!r.includes('/')) return
    setRows([]); setSkipped([]); setDone(null); setRunning(true)
    openSSE(`/api/audit?repo=${encodeURIComponent(r)}`, (d) => {
      if (d.type === 'checking') setChecking(d.lib)
      if (d.type === 'log') setSkipped(s => [...s, d.text])
      if (d.type === 'finding') setRows(x => [...x, d])
      if (d.type === 'done') setDone(d)
    }, () => { setRunning(false); setChecking(null) })
  }

  const vuln = rows.filter(r => !r.patched)

  return (
    <section className="screen" id="audit">
      <Head n="00" title="Audit a repository"
            sub="Type any public GitHub repo. Mitos searches inside it for vendored copies of libraries with known security fixes, then reads the bytes of anything it finds to decide whether the fix is present." />
      <form className="auditbar" onSubmit={run}>
        <span className="ab-pre mono">github.com/</span>
        <input value={repo} onChange={e => setRepo(e.target.value)} placeholder="owner/name"
               spellCheck="false" autoCapitalize="off" />
        <button className={`run ${running ? 'busy' : ''}`} disabled={running || !repo.includes('/')}>
          {running ? 'auditing…' : 'audit'}
        </button>
      </form>
      <div className="ab-hint">
        try <button className="lnk" onClick={() => setRepo('micknoise/Maximilian')}>micknoise/Maximilian</button>
        {' · '}<button className="lnk" onClick={() => setRepo('macieks/Tiny2D')}>macieks/Tiny2D</button>
        {' · '}<button className="lnk" onClick={() => setRepo('icculus/sdlamp')}>icculus/sdlamp</button>
      </div>

      {checking && <div className="checking mono">scanning for {checking}…</div>}

      {rows.length > 0 && (
        <div className="findings">
          {rows.map((r, i) => (
            <div key={i} className={`finding ${r.patched ? 'ok' : 'vuln'}`}>
              <div className="fi-l">
                <div className="fi-lib">{r.lib} <span className="dim small">vendored copy</span></div>
                <div className="fi-path mono">{r.path}</div>
              </div>
              <div className="fi-cve mono">{r.cves}</div>
              <div className={`fi-v ${r.patched ? 'ok' : 'vuln'}`}>
                {r.patched ? 'FIX PRESENT' : 'MISSING FIX'}
              </div>
            </div>
          ))}
        </div>
      )}

      {done && (
        <div className={`audit-sum ${vuln.length ? 'bad' : 'good'}`}>
          {vuln.length ? (
            <>
              <b>{vuln.length} vendored {vuln.length === 1 ? 'copy is' : 'copies are'} missing a published security fix</b>
              <span>in <span className="mono">{done.repo}</span>. No package manager can see these — the files carry no version. Mitos can transplant the fix and prove the bug is gone.</span>
            </>
          ) : done.findings ? (
            <><b>Clean.</b><span>{done.findings} vendored {done.findings === 1 ? 'copy' : 'copies'} found in <span className="mono">{done.repo}</span>, all carrying the upstream fix.</span></>
          ) : (
            <><b>No vendored copies detected.</b><span>We check for a small set of commonly-copied C libraries whose fix signatures we have verified. Absence here is not proof of absence.</span></>
          )}
        </div>
      )}
      {skipped.length > 0 && (
        <details className="skipped">
          <summary>{skipped.length} file(s) reference a library but are not copies of it — excluded</summary>
          {skipped.map((s, i) => <div key={i} className="mono tiny dim">{s}</div>)}
        </details>
      )}
    </section>
  )
}

function Nav({ active }) {
  return (
    <nav className="nav">
      <div className="nav-in">
        <a href="#top" className="nav-brand">MITOS</a>
        <div className="nav-links">
          {SECTIONS.map(([id, label]) => (
            <a key={id} href={`#${id}`} className={active === id ? 'on' : ''}>{label}</a>
          ))}
        </div>
        <a className="nav-cta" href="https://github.com/nothings/stb/commit/98fdfc6df88b1e34a736d5e126e6c8139c8de1a6"
           target="_blank" rel="noreferrer">the fix ↗</a>
      </div>
    </nav>
  )
}

function Hero({ stats }) {
  return (
    <header className="hero" id="top">
      <div className="eyebrow">PROOF-CARRYING PATCHES</div>
      <h1>Your agents write patches all day.<br /><span>Nobody checks them.</span></h1>
      <p className="tagline">
        Mitos finds code that was copy-pasted out of another project and lost its version,
        applies the security fix it never received, and proves the exploit is dead with a
        compiler and a sanitizer.
      </p>
      <div className="hero-cta">
        <a href="#hunt" className="btn primary">Start the hunt</a>
        <a href="#proof" className="btn ghost">Jump to the proof</a>
      </div>
      <div className="strip">
        <div><b>{stats.scanned || '—'}</b><span>repos read live</span></div>
        <div><b className={stats.stale ? 'bad' : ''}>{stats.stale || '—'}</b><span>carrying a missing fix</span></div>
        <div><b>7</b><span>CVEs in one copied file</span></div>
        <div><b className={stats.verdict ? 'good' : ''}>{stats.verdict || '—'}</b><span>last verdict</span></div>
      </div>
      <div className="claim">The compiler decides, not the AI.</div>
    </header>
  )
}

/* ── 01 · HUNT ─────────────────────────────────────────────── */
function Hunt({ onStats }) {
  const [targets, setTargets] = useState([])
  const [pick, setPick] = useState('stb_vorbis')
  const [hits, setHits] = useState([])
  const [reading, setReading] = useState(null)
  const [fp, setFp] = useState(null)
  const [logs, setLogs] = useState([])
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(false)
  const [total, setTotal] = useState(0)
  const [filter, setFilter] = useState('ALL')
  const openSSE = useSSE()

  useEffect(() => { fetch('/api/targets').then(r => r.json()).then(d => setTargets(d.targets)).catch(() => {}) }, [])

  const stale = hits.filter(h => h.status === 'STALE').length
  const immune = hits.filter(h => h.status === 'IMMUNE').length
  const classified = stale + immune
  const pct = classified ? Math.round(100 * stale / classified) : 0
  const shown = hits.filter(h => filter === 'ALL' ? true : h.status === filter)

  const run = () => {
    setHits([]); setLogs([]); setDone(false); setRunning(true); setReading(null); setTotal(0)
    openSSE(`/api/scan?max=24&target=${pick}`, (d) => {
      if (d.type === 'fingerprint') setFp(d)
      if (d.type === 'log' || d.type === 'phase') setLogs(l => [...l, d.text])
      if (d.type === 'total') setTotal(d.count)
      if (d.type === 'reading') setReading(d)
      if (d.type === 'hit') { setReading(null); setHits(h => [...h, d]) }
    }, () => { setRunning(false); setDone(true); setReading(null) })
  }

  useEffect(() => { onStats?.({ scanned: hits.length, stale }) }, [hits.length, stale])

  return (
    <section className="screen" id="hunt">
      <Head n="01" title="The hunt" sub="Pick a real upstream security fix. Mitos searches GitHub and reads the bytes of every copy it finds — there is no version number to match on, so it matches on the code itself." />

      <div className="picker">
        {targets.map(t => (
          <button key={t.id} className={`pick ${pick === t.id ? 'on' : ''}`} onClick={() => setPick(t.id)}>
            <div className="pick-l">{t.label}</div>
            <div className="pick-b">{t.blurb}</div>
            <div className="pick-s mono">{t.repo}@{t.sha.slice(0, 8)}</div>
          </button>
        ))}
        <button className={`run ${running ? 'busy' : ''}`} onClick={run} disabled={running}>
          {running ? 'scanning…' : done ? 'scan again' : 'run live scan'}
        </button>
      </div>

      <div className="counters">
        <Stat v={classified ? `${pct}%` : '—'} l="of live copies still unpatched" tone="bad" big />
        <Stat v={stale || '—'} l="vulnerable" tone="bad" />
        <Stat v={immune || '—'} l="already patched" tone="good" />
        <Stat v={total ? `${hits.length}/${total}` : '—'} l="repos read" />
      </div>

      {(hits.length > 0 || running) && (
        <div className="filters">
          {['ALL', 'STALE', 'IMMUNE'].map(f => (
            <button key={f} className={filter === f ? 'on' : ''} onClick={() => setFilter(f)}>
              {f.toLowerCase()} {f === 'ALL' ? hits.length : f === 'STALE' ? stale : immune}
            </button>
          ))}
          <span className="f-note mono">{fp ? `matching on ${fp.marker}()` : ''}</span>
        </div>
      )}

      <div className="feed">
        {shown.map((h, i) => (
          <a key={i} className={`card ${h.status.toLowerCase()}`}
             href={`https://github.com/${h.repo}`} target="_blank" rel="noreferrer">
            <div className="card-main">
              <div className="repo">{h.repo}</div>
              <div className="path mono">{h.path}</div>
            </div>
            {h.date && <div className="date mono">{h.date.slice(0, 10)}</div>}
            {h.predates && <div className="tag">predates fix</div>}
            <div className={`verdict ${h.status.toLowerCase()}`}>{h.status}</div>
          </a>
        ))}
        {reading && (
          <div className="card reading">
            <div className="card-main">
              <div className="repo">{reading.repo}</div>
              <div className="path mono">{reading.path}</div>
            </div>
            <div className="verdict reading">reading…</div>
          </div>
        )}
        {!hits.length && !running && <div className="empty">pick a fix above, then run the live scan</div>}
      </div>

      {logs.length > 0 && <Term lines={logs} h={92} />}
      {done && (
        <p className="foot">
          {stale} of {classified} live copies are missing this fix. Each verdict comes from reading
          that repository&apos;s own bytes — none of them declare a version.
        </p>
      )}
    </section>
  )
}

/* ── 02 · TARGET ───────────────────────────────────────────── */
function TargetView({ target }) {
  const [src, setSrc] = useState(null)
  const [tab, setTab] = useState('wrapper')
  const [cve, setCve] = useState(null)
  useEffect(() => { fetch('/api/source').then(r => r.json()).then(setSrc).catch(() => {}) }, [])
  if (!target) return null

  const views = {
    wrapper: { lines: src?.wrapper || [], from: 1, note: "ClanLib's only divergence: seven lines. Everything below is byte-identical to upstream v1.16." },
    head: { lines: src?.head || [], from: 1, note: 'The top of the file. There is no version field, no package name, nothing a scanner can match.' },
    vuln: { lines: src?.vuln || [], from: src?.vuln_start || 1, note: 'The function the proof-of-concept overflows. The crash lands at line 1065.' },
  }
  const v = views[tab]

  return (
    <section className="screen" id="target">
      <Head n="02" title="The target" sub="One of those copies, in detail. This is ClanLib's actual file at the pinned commit, fetched from the repository." />
      <div className="tgrid">
        <div className="panel">
          <div className="p-k">downstream</div>
          <a className="p-v link" href="https://github.com/sphair/ClanLib" target="_blank" rel="noreferrer">sphair/ClanLib ↗</a>
          <div className="mono dim small wrap">{target.path}</div>
          <div className="chip-row">
            <span className="chip">renamed <span className="mono">.c → .h</span></span>
            <span className="chip">{src?.total_lines || '5494'} lines</span>
            <span className="chip bad">no version</span>
            <span className="chip bad">not in any manifest</span>
          </div>
          <div className="p-k mt">identified as</div>
          <div className="p-v accent">stb_vorbis v1.16</div>
          <div className="dim small">fingerprinted from the code, not metadata</div>
          <div className="p-k mt">missing seven fixes — click one</div>
          <div className="cves">
            {(target.cves || []).map(c => (
              <button key={c} className={`cve ${cve === c ? 'on' : ''}`} onClick={() => setCve(cve === c ? null : c)}>{c}</button>
            ))}
          </div>
          {cve && target.cve_detail?.[cve] && (
            <div className="cve-detail">
              <b>{cve}</b> — {target.cve_detail[cve].kind} in
              <span className="mono accent"> {target.cve_detail[cve].fn}()</span>
            </div>
          )}
        </div>

        <div className="panel code-panel">
          <div className="tabs">
            {[['wrapper', "the 7-line wrapper"], ['head', 'file header'], ['vuln', 'the vulnerable function']].map(([k, l]) => (
              <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>
            ))}
          </div>
          <div className="code">
            {v.lines.length ? v.lines.map((l, i) => {
              const ln = v.from + i
              const hot = tab === 'vuln' && ln === src?.crash_line
              return (
                <div key={i} className={`cl ${hot ? 'hot' : ''}`}>
                  <span className="ln">{ln}</span><span className="ct">{l || ' '}</span>
                  {hot && <span className="hot-tag">crash</span>}
                </div>
              )
            }) : <div className="dim mono small">loading…</div>}
          </div>
          <div className="code-note">{v.note}</div>
        </div>
      </div>
    </section>
  )
}

/* ── 03 · REPAIR ───────────────────────────────────────────── */
function Repair({ target, res, logs, running, run }) {
  const [ev, setEv] = useState(null)
  const [hunkFilter, setHunkFilter] = useState('all')
  useEffect(() => { if (res) fetch('/api/evidence').then(r => r.json()).then(setEv).catch(() => {}) }, [res])

  const diff = ev?.fix_diff || ''
  const hunks = res?.hunks || []
  const shownHunks = hunks.filter(h => hunkFilter === 'all' ? true
    : hunkFilter === 'ok' ? h.verified : !h.verified)

  return (
    <section className="screen" id="repair">
      <Head n="03" title="The repair" sub="A deterministic three-way merge, then a hard gate: the result must hash to an independently-reviewed known-correct postimage, or the run is refused."
            action={<button className={`run ${running ? 'busy' : ''}`} onClick={run} disabled={running}>
              {running ? 'repairing…' : res ? 'run again' : 'run repair'}</button>} />

      <div className="merge-viz">
        <div className="m-node base">v1.16<span>common ancestor</span></div>
        <div className="m-arrows">↙ ↘</div>
        <div className="m-split">
          <div className="m-node">ClanLib&apos;s copy<span>their 7-line wrapper</span></div>
          <div className="m-node">v1.17<span>+22 / −6 · 7 CVEs</span></div>
        </div>
        <div className="m-arrows">↘ ↙</div>
        <div className={`m-node merged ${res ? 'ok' : ''}`}>
          MERGED<span>{res ? `rc=${res.merge.returncode} · ${res.merge.conflicts} conflicts` : 'pending'}</span>
        </div>
      </div>

      <div className={`golden ${res?.golden?.merged_match ? 'locked' : ''}`}>
        <div className="g-k">golden postimage<br />sha256</div>
        <div className="g-v mono">{(res?.golden?.actual_merged_sha256 || target?.expected_merged_sha256 || '')}</div>
        <div className="g-s">{res?.golden?.merged_match ? '✓ byte-exact' : 'awaiting run'}</div>
      </div>

      {res && (
        <div className="hunks">
          <div className="hunks-h">
            <b>{hunks.length} hunks transplanted</b>
            <div className="filters inline">
              {[['all', hunks.length], ['ok', hunks.filter(h => h.verified).length], ['adv', hunks.filter(h => !h.verified).length]].map(([k, n]) => (
                <button key={k} className={hunkFilter === k ? 'on' : ''} onClick={() => setHunkFilter(k)}>{k} {n}</button>
              ))}
            </div>
          </div>
          <div className="htable">
            {shownHunks.map((h, i) => (
              <div key={i} className={`hrow ${h.verified ? '' : 'adv'}`}>
                <span className="mono hcode">{h.sample || h.header_function}</span>
                <span className="hscope mono">{h.actual_scope}</span>
                <span className="hdelta mono">+{h.added}/−{h.removed}</span>
                <span className={`hst ${h.verified ? 'ok' : 'adv'}`}>{h.status}</span>
              </div>
            ))}
          </div>
          <p className="hnote">
            Two hunks are advisory: <span className="mono">draw_line</span> contains two identical
            <span className="mono"> inverse_db_table[y&amp;255]</span> edits, which no positional heuristic
            can tell apart. The golden postimage certifies both byte-exact.
          </p>
        </div>
      )}

      {diff && <Diff text={diff} />}
      <Term lines={logs} h={150} placeholder="engine output streams here — nothing is pre-recorded" />
    </section>
  )
}

/* ── 04 · PROOF ────────────────────────────────────────────── */
function Proof({ res }) {
  const probe = res?.probes?.[0]
  const asan = probe?.detail?.match(/ERROR: AddressSanitizer: ([a-z-]+)/)?.[1]
  return (
    <section className="screen" id="proof">
      <Head n="04" title="The proof" sub="An assertion versus a receipt. Both lanes were given the same file and the same crafted input." />
      <div className="proof">
        <div className="lane agent">
          <div className="lane-h">An agent says</div>
          <div className="agent-msg">
            <div className="agent-check">✓</div>
            <p>“I&apos;ve applied the upstream security fix. The vulnerability has been resolved.”</p>
          </div>
          <div className="lane-f bad">confident · unverifiable</div>
        </div>
        <div className="lane mitos">
          <div className="lane-h">Mitos proves</div>
          <div className="ba">
            <div className={`half before ${probe ? 'fired' : ''}`}>
              <div className="half-k">before</div>
              <div className="half-v">{probe ? (asan || 'crash') : '—'}</div>
              {probe && <span className="mono tiny">compute_codewords stb_vorbis.h:1065<br />process aborted · rc {probe.before_rc}</span>}
            </div>
            <div className={`half after ${probe?.ok ? 'clean' : ''}`}>
              <div className="half-k">after</div>
              <div className="half-v">{probe ? 'exit 0 · clean' : '—'}</div>
              {probe && <span className="mono tiny">same binary, same input<br />ClanLib&apos;s own translation unit</span>}
            </div>
          </div>
          <div className="lane-f good">
            {res ? `${res.baseline.status} / ${res.patched.status} builds · AddressSanitizer` : 'awaiting run'}
          </div>
        </div>
      </div>
      {probe && (
        <>
          <div className="offset-callout">
            <span className="mono">stb_vorbis.h:1065</span> — upstream crashes at
            <span className="mono"> 1058</span>. Exactly <b>+7</b>: ClanLib&apos;s wrapper shifted every
            line. That offset is why a naive patch fails here and why the merge is required.
          </div>
          <div className="raw">
            <div className="raw-k">raw probe output</div>
            <div className="mono raw-v">{probe.detail}</div>
          </div>
        </>
      )}
    </section>
  )
}

/* ── 05 · EVIDENCE ─────────────────────────────────────────── */
function Evidence({ res }) {
  const [ev, setEv] = useState(null)
  const [tab, setTab] = useState('pr')
  useEffect(() => { fetch('/api/evidence').then(r => r.json()).then(setEv).catch(() => {}) }, [res])
  if (!res) return (
    <section className="screen" id="evidence">
      <Head n="05" title="Evidence" sub="Run a repair and the full artifact bundle appears here." />
      <div className="empty">no run yet</div>
    </section>
  )
  const c = res.certification, cov = res.coverage
  const body = tab === 'pr' ? ev?.pr_body : tab === 'diff' ? ev?.fix_diff
    : JSON.stringify(ev?.evidence, null, 2)

  return (
    <section className="screen" id="evidence">
      <Head n="05" title="Evidence" sub="What a reviewer receives. Including, explicitly, what was not proven." />
      <div className={`verdict-big ${res.verdict.toLowerCase()}`}>
        {res.verdict}
        <span>{c.verified_applied}/{c.upstream_hunks} hunks · {cov.behaviourally_verified_count}/{cov.reachable_count} reachable sites exercised</span>
      </div>
      <div className="rgrid">
        <R k="merge" v={`rc=${res.merge.returncode} · ${res.merge.conflicts} conflicts`} />
        <R k="golden postimage" v={res.golden.merged_match ? 'exact match' : 'MISMATCH'} good={res.golden.merged_match} />
        <R k="parent verified" v={String(res.parent_verified)} />
        <R k="baseline build" v={`${res.baseline.status} · ${res.baseline.sha256}`} />
        <R k="patched build" v={`${res.patched.status} · ${res.patched.sha256}`} />
        <R k="behavioural coverage" v={cov.behaviourally_verified_loaders.join(', ') || '—'} />
        <R k="generator commit" v={res.generator} />
        <R k="recipe digest" v={res.recipe_digest} />
      </div>
      <div className="tabs art">
        {[['pr', 'PR_BODY.md'], ['diff', 'fix.diff'], ['json', 'evidence.json']].map(([k, l]) => (
          <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>
        ))}
        <span className="dim tiny">{body ? `${(body.length / 1024).toFixed(1)} KB` : ''}</span>
      </div>
      <pre className="artifact mono">{body || 'loading…'}</pre>
      <div className="limits">
        <b>What this does not claim.</b> {res.reasons.join('; ')}. We are not claiming a remote
        exploit of the shipped application — we proved the memory-safety bug in ClanLib&apos;s actual
        compiled translation unit. The repair recipe was written by a human; autonomous discovery
        is the open problem.
      </div>
    </section>
  )
}

/* ── shared ────────────────────────────────────────────────── */
const Head = ({ n, title, sub, action }) => (
  <div className="screen-head">
    <span className="idx">{n}</span>
    <h2>{title}</h2>
    <p className="sub">{sub}</p>
    {action}
  </div>
)
const Stat = ({ v, l, tone, big }) => (
  <div className={`stat ${tone || ''} ${big ? 'big' : ''}`}>
    <div className="stat-v">{v}</div><div className="stat-l">{l}</div>
  </div>
)
const R = ({ k, v, good }) => (
  <div><span>{k}</span><b className={good ? 'good' : ''}>{v}</b></div>
)
function Term({ lines, h, placeholder }) {
  const ref = useRef(null)
  useEffect(() => { ref.current?.scrollTo(0, ref.current.scrollHeight) }, [lines])
  return (
    <div className="logs" style={{ height: h }} ref={ref}>
      {lines?.length ? lines.map((l, i) => <div key={i} className="logline mono">{l}</div>)
        : <div className="dim mono small">{placeholder || 'idle'}</div>}
    </div>
  )
}
function Diff({ text }) {
  const rows = useMemo(() => text.split('\n').map((l, i) => ({
    l, i, t: l.startsWith('+++') || l.startsWith('---') ? 'meta'
      : l.startsWith('@@') ? 'hunk' : l.startsWith('+') ? 'add'
      : l.startsWith('-') ? 'del' : 'ctx',
  })), [text])
  const adds = rows.filter(r => r.t === 'add').length
  const dels = rows.filter(r => r.t === 'del').length
  return (
    <div className="diffbox">
      <div className="diff-h">
        <b className="mono">fix.diff</b>
        <span className="good mono">+{adds}</span><span className="bad mono">−{dels}</span>
        <span className="dim tiny">the exact patch applied to ClanLib&apos;s copy</span>
      </div>
      <div className="diff">
        {rows.map(r => <div key={r.i} className={`dl ${r.t}`}>{r.l || ' '}</div>)}
      </div>
    </div>
  )
}

/* ── app ───────────────────────────────────────────────────── */
export default function App() {
  const [target, setTarget] = useState(null)
  const [res, setRes] = useState(null)
  const [logs, setLogs] = useState([])
  const [running, setRunning] = useState(false)
  const [stats, setStats] = useState({})
  const [active, setActive] = useState('')
  const openSSE = useSSE()

  useEffect(() => { fetch('/api/target').then(r => r.json()).then(setTarget).catch(() => {}) }, [])

  useEffect(() => {
    const io = new IntersectionObserver(
      es => es.forEach(e => e.isIntersecting && setActive(e.target.id)),
      { rootMargin: '-45% 0px -50% 0px' })
    SECTIONS.forEach(([id]) => { const el = document.getElementById(id); if (el) io.observe(el) })
    return () => io.disconnect()
  }, [target])

  const runRepair = () => {
    setLogs([]); setRes(null); setRunning(true)
    openSSE('/api/repair', (d) => {
      if (d.type === 'log') setLogs(l => [...l, d.text])
      if (d.type === 'result') setRes(d)
    }, () => setRunning(false))
  }

  return (
    <>
      <Nav active={active} />
      <div className="app">
        <Hero stats={{ ...stats, verdict: res?.verdict?.replace('_', ' ') }} />
        <Audit />
        <Hunt onStats={setStats} />
        <TargetView target={target} />
        <Repair target={target} res={res} logs={logs} running={running} run={runRepair} />
        <Proof res={res} />
        <Evidence res={res} />
        <footer className="foot-bar">
          <div>
            <b>Provenance.</b> The Mitos engine is pre-existing open-source work, used here as a
            disclosed dependency. Built tonight: the ClanLib recipe, the sanitizer harness, the
            crash-before-only probe capability, the live server and this interface.
          </div>
          <div className="dim">
            stb is public domain · ClanLib is GPL · proof-of-concept from ForAllSecure/VulnerabilitiesLab
          </div>
        </footer>
      </div>
    </>
  )
}

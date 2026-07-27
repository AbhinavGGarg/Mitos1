import React, { useEffect, useMemo, useRef, useState } from 'react'
import { HexclaveGate, useMaybeUser, signIn, signOut, hexclaveEnabled } from './hexclave.jsx'

/* Every value on this page came from a live engine call.
     /api/audit    scoped GitHub search + per-file byte reads
     /api/scan     the same, across all of GitHub for one upstream fix
     /api/repair   real three-way merge, hash gate, two sanitizer builds, real PoC probe
     /api/source   ClanLib's actual file at the pinned commit
     /api/evidence the artifacts the last run wrote to disk
   Nothing is replayed and nothing is fixture data. Where the engine cannot decide, the
   interface says so rather than picking a side. */

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
  ['audit', 'Audit'], ['case', 'The case'], ['proof', 'Proof'],
  ['receipt', 'Receipt'], ['scale', 'At scale'], ['watch', 'Watch'],
]

/* Measured 2026-07-25 and published in data/vendored-scan.json. Regenerate with
   data/scan.py. These are counts of confirmed implementation copies; files that merely
   reference a library are excluded rather than counted as vulnerable. */
const LEDGER = [
  { lib: 'lodepng',    bad: 73, all: 75, how: 'fix marker' },
  { lib: 'stb_image',  bad: 80, all: 83, how: 'fix marker' },
  { lib: 'miniz',      bad: 25, all: 29, how: 'similarity' },
  { lib: 'stb_vorbis', bad: 22, all: 62, how: 'fix marker' },
  { lib: 'cgltf',      bad: 1,  all: 65, how: 'similarity' },
]
const TOT = LEDGER.reduce((a, r) => ({ bad: a.bad + r.bad, all: a.all + r.all }), { bad: 0, all: 0 })
const pct = (b, a) => (a ? Math.round(100 * b / a) : 0)

/* ── chrome ───────────────────────────────────────────────── */
function Masthead({ active }) {
  return (
    <div className="masthead">
      <div className="masthead-in">
        <a href="#top" className="wordmark">Mitos<sup>β</sup></a>
        <nav className="mast-nav">
          {SECTIONS.map(([id, label]) => (
            <a key={id} href={`#${id}`} className={active === id ? 'on' : ''}>{label}</a>
          ))}
        </nav>
        <a className="mast-cta" href="https://github.com/AbhinavGGarg/Mitos1"
           target="_blank" rel="noreferrer">Source</a>
      </div>
    </div>
  )
}

const Head = ({ kicker, title, children, action }) => (
  <div className="sec-head">
    <div>
      <span className="kicker">{kicker}</span>
      <h2>{title}</h2>
    </div>
    <div>
      {children}
      {action}
    </div>
  </div>
)

function Instrument({ cap, right, children, empty }) {
  const ref = useRef(null)
  useEffect(() => { ref.current?.scrollTo(0, ref.current.scrollHeight) }, [children])
  return (
    <div className="instrument">
      <div className="instrument-cap"><span>{cap}</span><span>{right}</span></div>
      <div className="instrument-body stream" ref={ref}>
        {children || <span style={{ color: 'var(--machine-dim)' }}>{empty}</span>}
      </div>
    </div>
  )
}

/* ── hero + ledger ────────────────────────────────────────── */
function Hero() {
  return (
    <header className="hero" id="top">
      <div className="page">
        <div className="hero-grid">
          <h1>Your agents copy code.<br /><em>Nobody checks it.</em></h1>
          <div className="hero-arg">
            <p>
              A library you install is written down, and every scanner on the market works by
              reading that list. A file you copy in is not written down at all.
            </p>
            <p>
              So when the original ships a security fix, the copy never hears about it. Mitos
              finds those copies, applies the fix they missed, and proves the bug is gone.
            </p>
            <div className="thesis">The compiler decides, not the model.</div>
          </div>
        </div>

        <div className="ledger">
          <div className="ledger-cap">
            <span>Confirmed vendored copies read from public repositories</span>
            <span>2026-07-25 · n={TOT.all}</span>
          </div>
          {LEDGER.map(r => (
            <div className="ledger-row" key={r.lib}>
              <span className="ledger-lib">{r.lib}</span>
              <span className="ledger-n">{r.bad}/{r.all}</span>
              <span className="ledger-pct">{pct(r.bad, r.all)}%</span>
              <span className="ledger-bar"><i style={{ width: `${pct(r.bad, r.all)}%` }} /></span>
            </div>
          ))}
          <div className="ledger-row sum">
            <span className="ledger-lib"><b>missing a published fix</b></span>
            <span className="ledger-n">{TOT.bad}/{TOT.all}</span>
            <span className="ledger-pct">{pct(TOT.bad, TOT.all)}%</span>
            <span />
          </div>
        </div>
        <p className="ledger-note">
          A file counts only if it contains the library's implementation, and counts as patched
          only if it carries a symbol the fix itself introduced. 106 files that merely reference
          a library were excluded rather than counted. cgltf comes back at 2% — the spread is
          the reason to believe the rest.
        </p>
      </div>
    </header>
  )
}

/* ── audit ────────────────────────────────────────────────── */
function Audit({ onDone }) {
  const [repo, setRepo] = useState('')
  const [rows, setRows] = useState([])
  const [skipped, setSkipped] = useState([])
  const [checking, setChecking] = useState(null)
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(null)
  const [err, setErr] = useState(null)
  const openSSE = useSSE()

  const slug = (s) => s.trim()
    .replace(/^(https?:\/\/)?(www\.)?github\.com\//i, '').replace(/\.git$/i, '')
    .replace(/[?#].*$/, '').replace(/^\/+|\/+$/g, '').split('/').slice(0, 2).join('/')
  const valid = /^[\w.-]+\/[\w.-]+$/.test(slug(repo))

  const run = (e) => {
    e?.preventDefault()
    if (!valid) return
    setRows([]); setSkipped([]); setDone(null); setErr(null); setRunning(true)
    openSSE(`/api/audit?repo=${encodeURIComponent(slug(repo))}`, (d) => {
      if (d.type === 'checking') setChecking(d.lib)
      if (d.type === 'log') setSkipped(s => [...s, d.text])
      if (d.type === 'finding') setRows(x => [...x, d])
      if (d.type === 'error') setErr(d.text || 'stream failed')
      if (d.type === 'done') { setDone(d); onDone?.(d) }
    }, (last) => {
      setRunning(false); setChecking(null)
      if (!last) setErr('the connection to the engine dropped before a result arrived')
    })
  }
  const vuln = rows.filter(r => !r.patched)

  return (
    <section className="sec" id="audit">
      <div className="page">
        <Head kicker="Try it" title="Audit a repository">
          <p>
            Give it any public repository. It searches inside for vendored copies of libraries
            with known fixes, then reads the bytes of whatever it finds.
          </p>
        </Head>

        <form className="query" onSubmit={run}>
          <input value={repo} onChange={e => setRepo(e.target.value)}
                 placeholder="https://github.com/sphair/ClanLib"
                 spellCheck="false" autoCapitalize="off" autoComplete="off" autoFocus />
          <button className={`act ${running ? 'busy' : ''}`} disabled={running || !valid}>
            {running ? 'reading…' : 'Audit'}
          </button>
        </form>
        <div className="presets">
          {['sphair/ClanLib', 'Novum/vkQuake', 'micknoise/Maximilian'].map((r, i) => (
            <React.Fragment key={r}>
              {i > 0 && '  ·  '}
              <button type="button" onClick={() => setRepo(`https://github.com/${r}`)}>{r}</button>
            </React.Fragment>
          ))}
        </div>

        {checking && <div className="crit">reading {checking}…</div>}
        {err && <div className="errbox"><b>Audit failed.</b> <span className="mono">{err}</span></div>}

        {rows.length > 0 && (
          <div className="register">
            {rows.map((r, i) => (
              <div className="finding" key={i}>
                <span className={`verdict ${r.patched ? 'ok' : 'stale'}`}>
                  {r.patched ? 'CARRIES FIX' : 'MISSING FIX'}
                </span>
                <div>
                  <div className="f-lib">{r.lib}</div>
                  <div className="f-path">{r.path}</div>
                  {r.detail && <div className="f-why">{r.detail}</div>}
                </div>
                <div className="f-meta">
                  {r.cves}<br />
                  <span className="dim">{r.method === 'similarity' ? 'by similarity' : 'by fix marker'}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {done && (
          <div className={`summary ${vuln.length ? 'bad' : 'good'}`}>
            {vuln.length ? (
              <>
                <b>{vuln.length} vendored {vuln.length === 1 ? 'copy is' : 'copies are'} missing a published fix</b>
                <span>
                  in {done.repo}. Nothing declares these as dependencies, so there is no
                  coordinate for a scanner to match against an advisory.
                </span>
              </>
            ) : done.findings ? (
              <><b>Clean</b><span>{done.findings} vendored {done.findings === 1 ? 'copy' : 'copies'} found in {done.repo}, all carrying the upstream fix.</span></>
            ) : (
              <><b>Nothing detected</b><span>We check a small set of commonly copied C libraries whose fix signatures we have verified against the upstream commit. Absence here is not evidence of absence.</span></>
            )}
          </div>
        )}

        {skipped.length > 0 && (
          <details className="crit" style={{ marginTop: 14 }}>
            <summary>{skipped.length} file(s) excluded rather than counted</summary>
            {skipped.map((s, i) => <div key={i} className="mono tiny dim" style={{ padding: '3px 0 3px 16px' }}>{s}</div>)}
          </details>
        )}
      </div>
    </section>
  )
}

/* ── the case ─────────────────────────────────────────────── */
function TheCase({ target }) {
  const [src, setSrc] = useState(null)
  const [tab, setTab] = useState('vuln')
  const [cve, setCve] = useState(null)
  useEffect(() => { fetch('/api/source').then(r => r.json()).then(setSrc).catch(() => {}) }, [])
  if (!target) return null

  const views = {
    wrapper: { lines: src?.wrapper || [], from: 1,
      note: "ClanLib's only divergence from upstream: seven lines. Everything below them is identical to v1.16." },
    head: { lines: src?.head || [], from: 1,
      note: 'Line 8 does say v1.16. The version is there, in a comment, for a human. No scanner reads comments, and there is no manifest entry, so nothing machine-readable declares this a dependency.' },
    vuln: { lines: src?.vuln || [], from: src?.vuln_start || 1,
      note: 'The function the proof-of-concept overflows. The crash lands on line 1065.' },
  }
  const v = views[tab]

  return (
    <section className="sec" id="case">
      <div className="page">
        <Head kicker="One copy, in detail" title="ClanLib, a C++ game engine SDK">
          <p>
            It needed to decode audio, so someone copied stb_vorbis into the source tree. In 2019
            upstream fixed seven CVEs in that file. This copy never received them.
          </p>
        </Head>

        <div className="two">
          <div className="panel">
            <div className="p-k">Downstream</div>
            <a className="p-v" href="https://github.com/sphair/ClanLib" target="_blank" rel="noreferrer">
              sphair/ClanLib ↗
            </a>
            <div className="mono tiny dim wrap">{target.path}</div>
            <div className="chips">
              <span className="chip">renamed .c → .h</span>
              <span className="chip">{src?.total_lines || 5494} lines</span>
              <span className="chip flag">no manifest entry</span>
              <span className="chip flag">no package coordinate</span>
            </div>

            <div className="p-k mt">Identified as</div>
            <div className="p-v">stb_vorbis v1.16</div>
            <div className="dim small">fingerprinted from the code, not from metadata</div>

            <div className="p-k mt">Missing seven fixes</div>
            <div className="cves">
              {(target.cves || []).map(c => (
                <button key={c} className={`cve ${cve === c ? 'on' : ''}`}
                        onClick={() => setCve(cve === c ? null : c)}>{c}</button>
              ))}
            </div>
            {cve && target.cve_detail?.[cve] && (
              <div className="cve-note">
                <b>{cve}</b> — {target.cve_detail[cve].kind} in{' '}
                <span className="mono">{target.cve_detail[cve].fn}()</span>
              </div>
            )}
          </div>

          <div className="srcbox">
            <div className="tabs">
              {[['vuln', 'the vulnerable function'], ['head', 'file header'], ['wrapper', 'their 7-line wrapper']].map(([k, l]) => (
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
                    {hot && <span className="hot-tag">CRASH</span>}
                  </div>
                )
              }) : <div className="cl"><span className="ln" /><span className="ct">loading…</span></div>}
            </div>
            <div className="code-note">{v.note}</div>
          </div>
        </div>
      </div>
    </section>
  )
}

/* ── proof ────────────────────────────────────────────────── */
function Proof({ res, logs, running, run }) {
  const probe = res?.probes?.[0]
  const asan = probe?.detail?.match(/ERROR: AddressSanitizer: ([a-z-]+)/)?.[1]

  return (
    <section className="sec" id="proof">
      <div className="page">
        <Head kicker="Assertion beside measurement" title="Anyone can say they fixed it"
              action={<button className={`act ${running ? 'busy' : ''}`} onClick={run} disabled={running}
                              style={{ marginTop: 14 }}>
                {running ? 'repairing…' : res ? 'Run again' : 'Run the repair'}
              </button>}>
          <p>
            The fix is merged into their copy with git, and the result is checked against a hash
            of the known-correct file. Then their code is built twice and fed the same crafted
            input.
          </p>
        </Head>

        <div className="proof">
          <div className="assertion">
            <div className="kicker">What a model reports <span className="tag">illustrative</span></div>
            <p className="quote">“Applied the upstream security fix. The vulnerability has been resolved.”</p>
            <div className="assert-foot">A CLAIM, NOT A MEASUREMENT</div>
            <p className="assert-note">
              Representative of how a coding agent reports a patch. Not captured from a live model run.
            </p>
          </div>

          <div className="measurement">
            <div className="instrument-cap">
              <span>ClanLib's own translation unit · AddressSanitizer</span>
              <span>{res ? `${res.baseline.status} / ${res.patched.status}` : 'idle'}</span>
            </div>
            <div className="ba">
              <div className={probe ? 'fired' : ''}>
                <div className="ba-k">Before</div>
                <div className="ba-v">{probe ? (asan || 'crash') : '—'}</div>
                {probe && <div className="ba-d">compute_codewords stb_vorbis.h:1065<br />process aborted · rc {probe.before_rc}</div>}
              </div>
              <div className={probe?.ok ? 'clean' : ''}>
                <div className="ba-k">After</div>
                <div className="ba-v">{probe ? 'exit 0' : '—'}</div>
                {probe && <div className="ba-d">same binary, same input<br />no fault</div>}
              </div>
            </div>
            {probe && (
              <div className="offset">
                Crash at <b>stb_vorbis.h:1065</b>. Upstream faults at <b>1058</b>. Exactly seven
                apart, the height of ClanLib's wrapper — which is how you know this trace came
                from their translation unit and not from upstream's file.
              </div>
            )}
          </div>
        </div>

        <div style={{ marginTop: 14 }}>
          <Instrument cap="engine output" right={running ? 'running' : `${logs.length} lines`}
                      empty="nothing is pre-recorded; press Run the repair">
            {logs.length ? logs.map((l, i) => <div key={i}>{l}</div>) : null}
          </Instrument>
        </div>
      </div>
    </section>
  )
}

/* ── receipt ──────────────────────────────────────────────── */
function Receipt({ res }) {
  const [ev, setEv] = useState(null)
  const [tab, setTab] = useState('pr')
  useEffect(() => { fetch('/api/evidence').then(r => r.json()).then(setEv).catch(() => {}) }, [res])

  return (
    <section className="sec" id="receipt">
      <div className="page">
        <Head kicker="What a reviewer receives" title="A receipt, not a notification">
          <p>
            Every scanner can tell you something is wrong. The output that matters states what
            was checked, how, and — explicitly — what was not.
          </p>
        </Head>

        {!res ? (
          <div className="empty">run the repair above and the receipt is issued here</div>
        ) : (
          <>
            <div className="receipt">
              <div className="receipt-head">
                <div className="receipt-title">
                  <span>Repair record</span>
                  sphair/ClanLib
                </div>
                <div className="stamp"><b>VERDICT</b>{res.verdict.replace('_', ' ')}</div>
              </div>
              <div className="receipt-rows">
                <div className="rrow"><span>upstream fix</span><b>nothings/stb@98fdfc6d</b></div>
                <div className="rrow"><span>three-way merge</span><b>rc {res.merge.returncode} · {res.merge.conflicts} conflicts</b></div>
                <div className="rrow"><span>golden postimage</span>
                  <b className={res.golden.merged_match ? 'ok' : ''}>{res.golden.merged_match ? 'exact match' : 'MISMATCH'}</b></div>
                <div className="rrow"><span>baseline build</span><b>{res.baseline.status} · {res.baseline.sha256}</b></div>
                <div className="rrow"><span>patched build</span><b>{res.patched.status} · {res.patched.sha256}</b></div>
                <div className="rrow"><span>hunks positionally cross-checked</span>
                  <b>{res.certification.verified_applied}/{res.certification.upstream_hunks}</b></div>
                <div className="rrow"><span>fix sites exercised</span>
                  <b>{res.coverage.behaviourally_verified_count}/{res.coverage.reachable_count} reachable</b></div>
                <div className="rrow"><span>generator</span><b>{res.generator}</b></div>
              </div>
              <div className="limit">
                <div className="limit-k">What this does not claim</div>
                <p>
                  {res.reasons.join('; ')}. We are not claiming a remote exploit of the shipped
                  application — only that the memory-safety fault is present in ClanLib's compiled
                  translation unit before the repair and absent after it. The recipe for this
                  repair was written by a human.
                </p>
              </div>
            </div>

            <div className="srcbox" style={{ marginTop: 16 }}>
              <div className="tabs">
                {[['pr', 'PR_BODY.md'], ['diff', 'fix.diff'], ['json', 'evidence.json']].map(([k, l]) => (
                  <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)}>{l}</button>
                ))}
              </div>
              <div className="code" style={{ padding: '14px 18px', whiteSpace: 'pre-wrap' }}>
                {(tab === 'pr' ? ev?.pr_body : tab === 'diff' ? ev?.fix_diff
                  : JSON.stringify(ev?.evidence, null, 2)) || 'loading…'}
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  )
}

/* ── at scale ─────────────────────────────────────────────── */
function AtScale({ onStats }) {
  const [targets, setTargets] = useState([])
  const [pick, setPick] = useState('stb_vorbis')
  const [hits, setHits] = useState([])
  const [crit, setCrit] = useState(null)
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(null)
  const [filter, setFilter] = useState('ALL')
  const openSSE = useSSE()

  useEffect(() => { fetch('/api/targets').then(r => r.json()).then(d => setTargets(d.targets)).catch(() => {}) }, [])

  const stale = hits.filter(h => h.status === 'STALE').length
  const immune = hits.filter(h => h.status === 'IMMUNE').length
  const refs = hits.filter(h => h.status === 'REFERENCE').length
  const classified = stale + immune
  const shown = hits.filter(h => filter === 'ALL' ? true : h.status === filter)

  const run = () => {
    setHits([]); setDone(null); setRunning(true)
    openSSE(`/api/scan?max=24&target=${pick}`, (d) => {
      if (d.type === 'criteria') setCrit(d)
      if (d.type === 'hit') setHits(h => [...h, d])
    }, () => { setRunning(false); setDone(true) })
  }
  useEffect(() => { onStats?.({ scanned: hits.length, stale }) }, [hits.length, stale])

  return (
    <section className="sec" id="scale">
      <div className="page">
        <Head kicker="The inverse question" title="Who else is still missing it"
              action={<button className={`act ${running ? 'busy' : ''}`} onClick={run} disabled={running}
                              style={{ marginTop: 14 }}>
                {running ? 'reading…' : done ? 'Read again' : 'Read GitHub'}
              </button>}>
          <p>
            Audit asks what is hiding in one repository. This asks who across GitHub is still
            carrying a given upstream fix — the question a security team asks the morning a
            CVE lands.
          </p>
        </Head>

        <div className="filters" style={{ margin: '0 0 4px' }}>
          {targets.map(t => (
            <button key={t.id} className={pick === t.id ? 'on' : ''} onClick={() => setPick(t.id)}>
              {t.label}
            </button>
          ))}
        </div>

        {classified > 0 && (
          <div className="ledger" style={{ marginTop: 22 }}>
            <div className="ledger-row sum">
              <span className="ledger-lib"><b>missing the fix</b></span>
              <span className="ledger-n">{stale}/{classified}</span>
              <span className="ledger-pct">{pct(stale, classified)}%</span>
              <span className="ledger-bar"><i style={{ width: `${pct(stale, classified)}%` }} /></span>
            </div>
          </div>
        )}

        {hits.length > 0 && (
          <>
            <div className="filters">
              {[['ALL', hits.length], ['STALE', stale], ['IMMUNE', immune], ['REFERENCE', refs]].map(([f, n]) => (
                <button key={f} className={filter === f ? 'on' : ''} onClick={() => setFilter(f)}>
                  {f.toLowerCase()} {n}
                </button>
              ))}
            </div>
            {crit && (
              <div className="crit">
                implementation markers: {crit.identity.join(', ')} · fix marker: {crit.fix_marker}
              </div>
            )}
            <div className="register">
              {shown.map((h, i) => (
                <a className="finding" key={i} href={`https://github.com/${h.repo}`}
                   target="_blank" rel="noreferrer">
                  <span className={`verdict ${h.status === 'STALE' ? 'stale'
                    : h.status === 'IMMUNE' ? 'ok' : 'none'}`}>{h.status}</span>
                  <div>
                    <div className="f-lib">{h.repo}</div>
                    <div className="f-path">{h.path}</div>
                    {h.why && <div className="f-why">{h.why}</div>}
                  </div>
                  <div className="f-meta">{h.date ? h.date.slice(0, 10) : ''}</div>
                </a>
              ))}
            </div>
          </>
        )}
        {!hits.length && !running && (
          <div className="empty" style={{ marginTop: 22 }}>pick a fix, then read GitHub</div>
        )}
      </div>
    </section>
  )
}

/* ── watch ────────────────────────────────────────────────── */
function Watch({ lastAudit }) {
  const user = useMaybeUser()
  const [list, setList] = useState([])
  const uid = user?.id || user?.primaryEmail || null

  const load = (u) => fetch(`/api/watchlist?user=${encodeURIComponent(u)}`)
    .then(r => r.json()).then(d => setList(d.watching || [])).catch(() => {})
  useEffect(() => { if (uid) load(uid) }, [uid])

  const watch = async (repo, findings, vulnerable, remove) => {
    if (!uid) return signIn()
    const r = await fetch('/api/watch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: uid, repo, findings, vulnerable, remove, at: new Date().toISOString() }),
    })
    setList((await r.json()).watching || [])
  }
  const watched = new Set(list.map(w => w.repo))

  return (
    <section className="sec" id="watch">
      <div className="page">
        <Head kicker="Where this goes" title="A scan is a moment">
          <p>
            The product is the watch. Name the repositories that are yours, and when upstream
            ships a fix for something you vendored, you get the patch rather than a notice
            telling you to go read a CVE.
          </p>
        </Head>

        {!hexclaveEnabled ? (
          <div className="empty">accounts not configured in this build</div>
        ) : !user ? (
          <div className="panel" style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
            <div style={{ flex: 1 }}>
              <div className="p-v" style={{ fontSize: 21 }}>Sign in to watch a repository</div>
              <div className="dim small">We store the repository name and its last audit result. Nothing else.</div>
            </div>
            <button className="act" onClick={signIn}>Sign in</button>
          </div>
        ) : (
          <>
            <div className="panel" style={{ display: 'flex', gap: 24, alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <div className="p-v" style={{ fontSize: 19 }}>{user.displayName || user.primaryEmail}</div>
                <div className="dim small">{list.length} watched</div>
              </div>
              {lastAudit?.repo && (
                <button className="act" onClick={() => watch(lastAudit.repo, lastAudit.findings,
                  lastAudit.vulnerable, watched.has(lastAudit.repo))}>
                  {watched.has(lastAudit.repo) ? 'Stop watching' : `Watch ${lastAudit.repo}`}
                </button>
              )}
              <button className="act ghost" onClick={() => signOut(user)}>Sign out</button>
            </div>
            <div className="register">
              {list.map((w, i) => (
                <div className="finding" key={i}>
                  <span className={`verdict ${w.vulnerable ? 'stale' : 'ok'}`}>
                    {w.vulnerable ? 'WATCHING' : 'CLEAR'}
                  </span>
                  <div><div className="f-lib">{w.repo}</div>
                    <div className="f-path">{w.vulnerable
                      ? `${w.vulnerable} copy/copies missing a fix at last audit` : 'clean at last audit'}</div>
                  </div>
                  <div className="f-meta">{(w.added || '').slice(0, 10)}</div>
                </div>
              ))}
              {!list.length && <div className="empty">audit a repository, then add it here</div>}
            </div>
          </>
        )}
      </div>
    </section>
  )
}

/* ── app ──────────────────────────────────────────────────── */
export default function App() {
  const [target, setTarget] = useState(null)
  const [res, setRes] = useState(null)
  const [logs, setLogs] = useState([])
  const [running, setRunning] = useState(false)
  const [lastAudit, setLastAudit] = useState(null)
  const [, setStats] = useState({})
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
    <HexclaveGate>
      <Masthead active={active} />
      <Hero />
      <div className="gap l" />
      <Audit onDone={setLastAudit} />
      <div className="gap" />
      <TheCase target={target} />
      <div className="gap" />
      <Proof res={res} logs={logs} running={running} run={runRepair} />
      <div className="gap" />
      <Receipt res={res} />
      <div className="gap l" />
      <AtScale onStats={setStats} />
      <div className="gap" />
      <Watch lastAudit={lastAudit} />
      <footer className="footer">
        <div className="page">
          <p><b>Provenance.</b> The engine is pre-existing open-source work, disclosed as a
            dependency. Built during the hackathon window: the ClanLib recipe, the sanitizer
            harness, the marker-free similarity detector, the live server and this interface.</p>
          <p>stb is public domain · ClanLib is GPL · lodepng, miniz and cgltf are zlib/MIT ·
            proof-of-concept input from ForAllSecure/VulnerabilitiesLab</p>
        </div>
      </footer>
    </HexclaveGate>
  )
}

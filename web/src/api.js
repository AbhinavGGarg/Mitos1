/* One interface, two backends.
 *
 * Locally the Python server streams real engine work over SSE and can run the full repair.
 * On Vercel there is no compiler and no long-running process, so:
 *   - the audit runs as a serverless function (marker detection is only string matching)
 *   - target/source/evidence are served as artifacts baked from a real verified run
 *   - the repair cannot run at all, and `canRepair` is false so the UI says so
 *
 * Nothing here fabricates a result. When the deployment cannot do something, it reports
 * that it cannot do it.
 */

export const DEPLOYED = import.meta.env.VITE_DEPLOYED === '1'
export const canRepair = !DEPLOYED
export const canStream = !DEPLOYED
export const canScanAll = !DEPLOYED   // the whole-of-GitHub scan needs the streaming server

const json = (u) => fetch(u).then(r => r.json())

export const getTarget   = () => json(DEPLOYED ? '/static/target.json'   : '/api/target')
export const getSource   = () => json(DEPLOYED ? '/static/source.json'   : '/api/source')
export const getEvidence = () => json(DEPLOYED ? '/static/evidence.json' : '/api/evidence')
export const getTargets  = () => json(DEPLOYED ? '/static/targets.json'  : '/api/targets')

/* Repair cannot run in this runtime, and today the engine only runs human-authored recipes
   pinned to exact commits. So the offer is a queued request, not a fake button. The server
   re-runs the audit before accepting, which is why the client never sends findings. */
export const queueStatus = () =>
  (DEPLOYED ? fetch('/api/audit?queue=status').then(r => r.json()) : Promise.resolve({ open: false }))
    .catch(() => ({ open: false }))

export const requestRepair = (repo, contact, note) =>
  fetch('/api/audit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo, contact, note }),
  }).then(async (r) => {
    const d = await r.json().catch(() => ({}))
    if (!r.ok) throw new Error(d.error || 'the request could not be filed')
    return d
  })

/* The engine writes evidence.json to disk; the local server reshapes it into the payload the
   receipt renders. This does the same mapping client-side so the deployed build can show the
   receipt from a real verified run instead of an empty panel telling you to run a repair that
   this runtime cannot run. Same numbers, same file, read from the artifact rather than a
   live process — and the UI labels it as recorded. */
export function recordedResult(ev) {
  if (!ev) return null
  const short = (h) => (h || '').slice(0, 16)
  return {
    verdict: ev.verdict,
    reasons: ev.reasons || [],
    merge: ev.merge,
    golden: ev.golden_attestation,
    parent_verified: ev.parent_verified,
    baseline: { ok: ev.baseline_build?.ok, status: ev.baseline_build?.status,
                sha256: short(ev.baseline_build?.sha256) },
    patched: { ok: ev.patched_build?.ok, status: ev.patched_build?.status,
               sha256: short(ev.patched_build?.sha256) },
    probes: ev.probes || [],
    coverage: ev.coverage,
    certification: ev.hunk_certification,
    hunks: ev.hunks || [],
    upstream: ev.upstream,
    downstream: ev.downstream,
    generator: (ev.generator_commit || '').slice(0, 10),
    recipe_digest: (ev.recipe_digest || '').slice(0, 10),
    recorded: true,
  }
}

/** Audit a repository. Emits the same event shapes in both modes so callers don't branch. */
export function runAudit(repo, onEvent, onDone) {
  if (!DEPLOYED) {
    const es = new EventSource(`/api/audit?repo=${encodeURIComponent(repo)}`)
    es.onmessage = (e) => {
      const d = JSON.parse(e.data)
      onEvent(d)
      if (d.type === 'done' || d.type === 'error') { es.close(); onDone?.(d) }
    }
    es.onerror = () => { es.close(); onDone?.(null) }
    return () => es.close()
  }

  let cancelled = false
  fetch(`/api/audit?repo=${encodeURIComponent(repo)}`)
    .then(r => r.json())
    .then(d => {
      if (cancelled) return
      if (d.configured === false || d.error) {
        onEvent({ type: 'error', text: d.error || 'audit unavailable on this deployment' })
        return onDone?.({ type: 'error' })
      }
      ;(d.excluded || []).forEach(t => onEvent({ type: 'log', text: t }))
      ;(d.findings || []).forEach(f => onEvent({ type: 'finding', ...f }))
      const done = { type: 'done', repo: d.repo, checked: d.checked,
                     findings: (d.findings || []).length, vulnerable: d.vulnerable }
      onEvent(done); onDone?.(done)
    })
    .catch(e => {
      if (cancelled) return
      onEvent({ type: 'error', text: String(e) }); onDone?.(null)
    })
  return () => { cancelled = true }
}

import React, { Suspense } from 'react'

/* Hexclave powers accounts + email for the monitoring loop: you tell Mitos which repos
   you own, and when upstream ships a security fix for something you vendored, we mail
   you a verified patch.

   Everything here is CONDITIONAL. If VITE_HEXCLAVE_PROJECT_ID is unset the app renders
   exactly as it did before — no provider, no suspense boundary, no crash. */

const PROJECT_ID = import.meta.env.VITE_HEXCLAVE_PROJECT_ID
const API_URL = import.meta.env.VITE_HEXCLAVE_API_URL
const PUBLISHABLE_KEY = import.meta.env.VITE_HEXCLAVE_PUBLISHABLE_CLIENT_KEY
export const hexclaveEnabled = Boolean(PROJECT_ID && API_URL)

let mod = null, clientApp = null
if (hexclaveEnabled) {
  try {
    mod = await import('@hexclave/react')
    clientApp = new mod.HexclaveClientApp({
      projectId: PROJECT_ID,
      baseUrl: API_URL,
      ...(PUBLISHABLE_KEY ? { publishableClientKey: PUBLISHABLE_KEY } : {}),
      tokenStore: 'cookie',
      urls: { default: { type: 'hosted' } },
    })
  } catch (e) {
    console.warn('Hexclave unavailable, continuing without accounts:', e)
    mod = null; clientApp = null
  }
}

export const hexclaveApp = clientApp

export function HexclaveGate({ children }) {
  if (!mod || !clientApp) return children
  const { HexclaveProvider, HexclaveTheme } = mod
  return (
    <Suspense fallback={children}>
      <HexclaveProvider app={clientApp}>
        <HexclaveTheme>{children}</HexclaveTheme>
      </HexclaveProvider>
    </Suspense>
  )
}

/** Current user, or null when Hexclave is not configured. Never throws. */
export function useMaybeUser() {
  if (!mod) return null
  try {
    return mod.useUser({ or: 'return-null' }) ?? null
  } catch {
    return null
  }
}

export async function signIn() {
  if (clientApp) await clientApp.redirectToSignIn()
}
export async function signOut(user) {
  try { await user?.signOut?.() } catch { /* ignore */ }
}

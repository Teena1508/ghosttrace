import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync } from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')
const isWindows = process.platform === 'win32'

const HEALTH_URL = 'http://127.0.0.1:8000/health'
const WATCHDOG_INTERVAL_MS = 5000
// Consecutive failed health checks before a still-running but unresponsive backend is restarted
const MAX_FAILED_CHECKS = 4

const log = {
  ok: (msg: string) => console.log(`\x1b[32m✔ [GhostTrace] ${msg}\x1b[0m`),
  info: (msg: string) => console.log(`\x1b[36m⚡ [GhostTrace] ${msg}\x1b[0m`),
  warn: (msg: string) => console.log(`\x1b[33m⚠ [GhostTrace] ${msg}\x1b[0m`),
  error: (msg: string) => console.error(`\x1b[31m✖ [GhostTrace] ${msg}\x1b[0m`),
}

/**
 * Prefer the project virtualenv, which has the backend dependencies installed.
 * A bare `python3` on PATH is often a different interpreter without FastAPI/uvicorn.
 */
function resolvePython(): string {
  const venvPython = isWindows
    ? path.join(rootDir, '.venv', 'Scripts', 'python.exe')
    : path.join(rootDir, '.venv', 'bin', 'python3')
  if (existsSync(venvPython)) return venvPython
  return isWindows ? 'python' : 'python3'
}

function checkBackend(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, (res) => {
      res.resume()
      resolve(res.statusCode === 200)
    })
    req.on('error', () => resolve(false))
    req.setTimeout(2000, () => {
      req.destroy()
      resolve(false)
    })
  })
}

interface BackendSupervisor {
  child: ChildProcess | null
  failedChecks: number
  wasOnline: boolean
}

/**
 * Keeps the FastAPI backend online for as long as the Vite dev server runs:
 * starts it if nothing answers on :8000, and restarts it whenever it crashes,
 * is killed, or stops responding. An externally started backend is left alone.
 */
function startSupervisor(): BackendSupervisor {
  const state: BackendSupervisor = { child: null, failedChecks: 0, wasOnline: false }
  const python = resolvePython()

  const launch = () => {
    log.info(`Backend not detected — starting it with ${python}`)
    const recentOutput: string[] = []

    const child = spawn(
      python,
      [
        '-m', 'uvicorn', 'backend.app.main:app',
        '--host', '127.0.0.1', '--port', '8000',
        '--reload',
        '--reload-dir', 'backend',
        '--reload-dir', 'investigation_engine',
        '--reload-dir', 'evaluation',
      ],
      { cwd: rootDir, stdio: ['ignore', 'pipe', 'pipe'] }
    )
    state.child = child

    const capture = (chunk: Buffer) => {
      const text = chunk.toString()
      recentOutput.push(...text.split('\n').filter(Boolean))
      recentOutput.splice(0, Math.max(0, recentOutput.length - 30))
      if (text.includes('Traceback') || /\bERROR\b/.test(text)) {
        console.error('\x1b[31m[GhostTrace Backend]\x1b[0m', text.trimEnd())
      }
    }
    child.stdout?.on('data', capture)
    child.stderr?.on('data', capture)

    child.on('error', (err) => {
      log.error(`Could not start backend with "${python}": ${err.message}`)
    })

    child.on('exit', (code, signal) => {
      if (state.child === child) state.child = null
      if (code === 0) return
      log.warn(`Backend stopped (${signal ?? `exit code ${code}`}). Restarting automatically...`)
      if (recentOutput.length > 0) {
        console.error(recentOutput.slice(-10).join('\n'))
      }
    })
  }

  const tick = async () => {
    const online = await checkBackend()
    if (online) {
      if (!state.wasOnline) log.ok(`Backend is ONLINE at http://127.0.0.1:8000`)
      state.wasOnline = true
      state.failedChecks = 0
      return
    }

    if (state.wasOnline) log.warn('Backend went offline')
    state.wasOnline = false
    state.failedChecks += 1

    if (!state.child) {
      state.failedChecks = 0
      launch()
    } else if (state.failedChecks >= MAX_FAILED_CHECKS) {
      log.warn('Backend process is running but not responding — restarting it')
      state.failedChecks = 0
      state.child.kill()
    }
  }

  // Ctrl+C / closing the terminal already reach the child via its process group
  process.once('exit', () => state.child?.kill())

  void tick()
  setInterval(tick, WATCHDOG_INTERVAL_MS).unref()
  return state
}

function autoBackendPlugin(): Plugin {
  return {
    name: 'auto-backend-plugin',
    apply: 'serve',
    configureServer() {
      // Vite re-runs configureServer when the config reloads; keep a single supervisor per process
      const g = globalThis as typeof globalThis & { __ghosttraceBackend?: BackendSupervisor }
      g.__ghosttraceBackend ??= startSupervisor()
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), autoBackendPlugin()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})

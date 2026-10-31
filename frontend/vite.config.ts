import react from '@vitejs/plugin-react'
import { defineConfig, type Plugin } from 'vite'
import { spawn } from 'node:child_process'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')

function autoBackendPlugin(): Plugin {
  return {
    name: 'auto-backend-plugin',
    configureServer() {
      const checkBackend = (): Promise<boolean> => {
        return new Promise((resolve) => {
          const req = http.get('http://127.0.0.1:8000/health', (res) => {
            resolve(res.statusCode === 200)
          })
          req.on('error', () => resolve(false))
          req.setTimeout(1200, () => {
            req.destroy()
            resolve(false)
          })
        })
      }

      const launchBackend = async () => {
        const isRunning = await checkBackend()
        if (isRunning) {
          console.log('\x1b[32m✔ [GhostTrace] Backend is already running on http://127.0.0.1:8000\x1b[0m')
          return
        }

        console.log('\x1b[36m⚡ [GhostTrace] Backend not detected — auto-starting in background...\x1b[0m')

        const isWindows = process.platform === 'win32'
        const pythonCmd = isWindows ? 'python' : 'python3'

        const backendProc = spawn(
          pythonCmd,
          ['-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', '8000', '--reload'],
          {
            cwd: rootDir,
            stdio: 'pipe',
            shell: isWindows,
          }
        )

        backendProc.stdout?.on('data', (chunk) => {
          const str = chunk.toString()
          if (str.includes('Application startup complete') || str.includes('Uvicorn running')) {
            console.log('\x1b[32m✔ [GhostTrace] Backend server is ONLINE at http://127.0.0.1:8000\x1b[0m')
          }
        })

        backendProc.stderr?.on('data', (chunk) => {
          const str = chunk.toString()
          if (str.includes('ERROR') || str.includes('Traceback')) {
            console.error('\x1b[31m[GhostTrace Backend Error]\x1b[0m', str)
          }
        })

        backendProc.on('exit', (code) => {
          if (code !== 0 && code !== null) {
            console.log(`\x1b[33m⚠ [GhostTrace] Backend stopped (code ${code}). Restarting in 2s...\x1b[0m`)
            setTimeout(launchBackend, 2000)
          }
        })
      }

      launchBackend()
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

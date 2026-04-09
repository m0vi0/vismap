import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const clientDir = join(root, 'client')
const args = process.argv.slice(2)
const appUrl = 'http://127.0.0.1:5173'
const children = []

function spawnChild(command, commandArgs, options = {}) {
  const child = spawn(command, commandArgs, {
    cwd: options.cwd || root,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  })

  children.push(child)

  child.on('exit', (code, signal) => {
    children
      .filter((candidate) => candidate !== child && !candidate.killed)
      .forEach((candidate) => candidate.kill())

    if (signal) process.exit(1)
    process.exit(code || 0)
  })

  return child
}

function pythonCommand() {
  if (process.platform === 'win32') {
    return { command: 'py', args: ['-3'] }
  }

  return { command: 'python3', args: [] }
}

function shutdown() {
  children.filter((child) => !child.killed).forEach((child) => child.kill())
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

if (!existsSync(join(clientDir, 'node_modules'))) {
  const install = spawnChild('npm', ['install'], { cwd: clientDir })
  install.on('exit', (code) => {
    if (code !== 0) process.exit(code || 1)
    start()
  })
} else {
  start()
}

function start() {
  const python = pythonCommand()
  const serverArgs = [...python.args, 'server.py', '--app-url', appUrl, ...args]

  spawnChild(python.command, serverArgs)
  spawnChild('npm', ['run', 'dev', '--', '--host', '127.0.0.1'], { cwd: clientDir })
}

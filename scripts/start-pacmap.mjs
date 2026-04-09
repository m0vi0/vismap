import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const clientDir = join(root, 'client')
const args = process.argv.slice(2)

function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd || root,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  })

  if (result.status !== 0) {
    process.exit(result.status || 1)
  }
}

function pythonCommand() {
  if (process.platform === 'win32') {
    return { command: 'py', args: ['-3'] }
  }

  return { command: 'python3', args: [] }
}

if (!existsSync(join(clientDir, 'node_modules'))) {
  run('npm', ['install'], { cwd: clientDir })
}

run('npm', ['run', 'build'], { cwd: clientDir })

const python = pythonCommand()
run(python.command, [...python.args, 'server.py', ...args])

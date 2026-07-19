#!/usr/bin/env node
const fs = require('fs')
const path = require('path')
const { spawn } = require('child_process')

const srcRoot = process.env.CLAUDE_SKILLS_SRC || path.join(process.env.HOME, '.claude', 'skills')
const script = process.env.CLAUDE_SKILLS_SYNC_SCRIPT || path.join(process.env.HOME, 'backup', 'MY_SKILLS', 'scripts', 'sync_claude_workflow_skills.sh')
const debounceMs = Number(process.env.CLAUDE_SKILLS_SYNC_DEBOUNCE_MS || 3000)
const pollMs = Number(process.env.CLAUDE_SKILLS_SYNC_POLL_MS || 60000)

let timer = null
let running = false
let pending = false
let lastFingerprint = ''

function runSync(reason) {
  if (running) {
    pending = true
    return
  }

  running = true
  const child = spawn(script, [], {
    stdio: 'inherit',
    env: process.env,
  })

  child.on('exit', (code) => {
    running = false
    if (code !== 0) {
      console.error(`[claude-skills-sync] sync failed (${code}) after ${reason}`)
    }
    if (pending) {
      pending = false
      schedule('pending-change')
    }
  })
}

function schedule(reason) {
  clearTimeout(timer)
  timer = setTimeout(() => runSync(reason), debounceMs)
}

function walk(dir, out = []) {
  let entries = []
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true })
  } catch (_) {
    return out
  }

  for (const entry of entries) {
    if (entry.name === '.git' || entry.name === '__pycache__') continue
    const full = path.join(dir, entry.name)
    try {
      const st = fs.statSync(full)
      out.push(`${full}:${st.mtimeMs}:${st.size}`)
      if (entry.isDirectory()) walk(full, out)
    } catch (_) {}
  }
  return out
}

function fingerprint() {
  return walk(srcRoot).sort().join('\n')
}

function poll() {
  const next = fingerprint()
  if (lastFingerprint && next !== lastFingerprint) {
    schedule('poll-change')
  }
  lastFingerprint = next
}

runSync('startup')
lastFingerprint = fingerprint()

try {
  fs.watch(srcRoot, { recursive: true }, (_event, filename) => {
    if (!filename) return schedule('fswatch-change')
    if (filename.includes('__pycache__') || filename.endsWith('.pyc')) return
    schedule(`fswatch:${filename}`)
  })
  console.log(`[claude-skills-sync] watching ${srcRoot}`)
} catch (err) {
  console.error(`[claude-skills-sync] recursive fs.watch unavailable, falling back to polling: ${err.message}`)
}

setInterval(poll, pollMs)


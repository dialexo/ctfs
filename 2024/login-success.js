const fs = require('fs')

const text = fs.readFileSync('../.pm2/logs/ctf-out.log', { encoding: 'utf8' })

const lines = text.split('\n')

const successes = lines.filter(l => l.match(/.*\/login.*null.*/)).filter(l => l.match('token')).map(l => decodeURIComponent(l)).map(l => l.match(/\{.*\}/)).filter(e => e !== null).filter(l => { try { JSON.parse(l[0]); return true } catch { return false } }).map(l => [l['input'], JSON.parse(l[0])]).filter(e => e[1].value === null)

const names = successes.map(([l]) => l.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/)).filter(e => e).map(e => e[0])

const ids = [...new Set(names)]

const state = fs.readFileSync('state', { encoding: 'utf8' })

const pairs = state.split('\n').filter(e => e).map(e => e.split(':')).map(e => [e[0], e[1]])

let map = new Map(pairs)

console.log(ids.map(i => map.get(i)))
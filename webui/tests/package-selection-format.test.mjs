import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

function modules(dev) {
  const cache = new Map()
  function load(path) {
    if (cache.has(path)) return cache.get(path)
    const source = readFileSync(new URL(`../src/${path}.ts`, import.meta.url), 'utf8')
    const javascript = ts.transpileModule(source, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    }).outputText
    const module = { exports: {} }
    cache.set(path, module.exports)
    vm.runInNewContext(javascript, {
      module, exports: module.exports,
      window: { requestAnimationFrame: fn => fn(), setTimeout: fn => fn() },
      require(name) {
        if (name === 'kernelsu-alt') return {}
        if (name.endsWith('/utils/dev') || name === './utils/dev') return { isDev: () => dev }
        if (name.endsWith('/package_name')) return load('package_name')
        if (name === './config') return load('config')
        throw new Error(`Unexpected module ${name}`)
      },
    })
    return module.exports
  }
  return load
}

test('manual selection writes one plain package shared across profiles', async () => {
  const load = modules(true)
  const { Config } = load('config')
  const { AppList } = load('app_list/app_list')
  const config = new Config()
  const list = new AppList(config)
  await list.fetch()
  const entries = list.getTargetEntries().filter(entry => entry.packageName === 'com.example.app')
  assert.equal(entries.length, 2)
  list.setTargetSelected(entries[1], true)
  assert.deepEqual([...config.get('target')], ['com.example.app'])
  assert.ok(list.getTargetEntries().filter(entry => entry.packageName === 'com.example.app').every(entry => entry.selected))
  config.set('target', ['com.example.app@0', 'com.example.app@10', 'uid:1000', 'com.other.app'])
  list.setTargetSelected(entries[0], false)
  assert.deepEqual([...config.get('target')], ['uid:1000', 'com.other.app'])
})

test('recommended and system selections never create user suffixes', async () => {
  const load = modules(true)
  const { Config } = load('config')
  const { AppList } = load('app_list/app_list')
  const config = new Config()
  const list = new AppList(config)
  await list.fetch()
  await list.selectRecommended()
  assert.ok(config.get('target').length > 0)
  assert.ok(config.get('target').every(target => !target.includes('@')))
  config.set('target', ['com.example.app', 'com.google.android.gms@0', 'com.android.vending@0'])
  list.applySystemAppSelection(['com.google.android.gms@0', 'com.google.android.gsf'])
  assert.deepEqual([...config.get('target')].sort(), ['com.example.app', 'com.google.android.gms', 'com.google.android.gsf'].sort())
})

test('bulk identity targets cover selected system apps and all installed profiles only', async () => {
  const load = modules(true)
  const { Config } = load('config')
  const { AppList } = load('app_list/app_list')
  const config = new Config()
  const list = new AppList(config)
  await list.fetch()
  config.set('target', ['com.example.app', 'com.google.android.gms', 'com.missing.app', 'uid:1000'])
  assert.deepEqual([...list.getSelectedIdentityTargets()].sort(), [
    'com.example.app@0', 'com.example.app@10', 'com.google.android.gms@0',
  ].sort())
  config.set('target', ['com.example.app@10'])
  assert.deepEqual([...list.getSelectedIdentityTargets()], ['com.example.app@10'])
  config.set('target', [])
  assert.deepEqual([...list.getSelectedIdentityTargets()], [])
})

test('explicit save converts old package selectors, preserves UID and concurrent additions', async () => {
  const load = modules(false)
  const { ConfigOhMyKeyMint } = load('config_ohmykeymint')
  const { AppList } = load('app_list/app_list')
  let disk = ['com.example.app@0', 'com.example.app@10', 'uid:1000']
  let delta
  const config = new ConfigOhMyKeyMint({
    async getScoop() { return [...disk] },
    async updateScoop(added, removed) {
      delta = { added: [...added], removed: [...removed] }
      disk = [...new Set([...disk.filter(target => !removed.includes(target)), ...added])]
      return [...disk]
    },
  })
  await config.read()
  assert.deepEqual([...config.get('target')], disk)
  disk.push('com.concurrent.app')
  const list = new AppList(config)
  let observed
  list.subscribe(snapshot => { observed = [...snapshot.selectedPackages] })
  await list.save()
  assert.deepEqual(delta, { added: ['com.example.app'], removed: ['com.example.app@0', 'com.example.app@10'] })
  assert.deepEqual(observed.sort(), ['uid:1000', 'com.example.app', 'com.concurrent.app'].sort())
  assert.ok(disk.every(target => !target.includes('@')))
})

test('failed save keeps legacy selection and can retry the same migration', async () => {
  const load = modules(false)
  const { ConfigOhMyKeyMint } = load('config_ohmykeymint')
  let fail = true
  let count = 0
  const config = new ConfigOhMyKeyMint({
    async getScoop() { return ['com.example.app@0'] },
    async updateScoop(added, removed) {
      count++
      assert.deepEqual([...added], ['com.example.app'])
      assert.deepEqual([...removed], ['com.example.app@0'])
      if (fail) throw new Error('write failed')
      return [...added]
    },
  })
  await config.read()
  await assert.rejects(() => config.write(), /write failed/)
  assert.deepEqual([...config.get('target')], ['com.example.app@0'])
  fail = false
  await config.write()
  assert.equal(count, 2)
  assert.deepEqual([...config.get('target')], ['com.example.app'])
})

test('in-flight writes keep newer clicks and concurrent backend additions for the next save', async () => {
  const { ConfigOhMyKeyMint } = modules(false)('config_ohmykeymint')
  let disk = ['com.old.app', 'uid:1000']
  let release
  let calls = 0
  const config = new ConfigOhMyKeyMint({
    async getScoop() { return [...disk] },
    async updateScoop(added, removed) {
      calls++
      if (calls === 1) await new Promise(resolve => { release = resolve })
      disk = [...new Set([...disk.filter(target => !removed.includes(target)), ...added])]
      return [...disk]
    },
  })
  await config.read()
  config.set('target', ['com.first.app', 'uid:1000'])
  const firstWrite = config.write()
  config.set('target', ['com.second.app', 'uid:1000'])
  disk.push('com.concurrent.app')
  release()
  await firstWrite
  assert.deepEqual([...config.get('target')].sort(), ['com.second.app', 'com.concurrent.app', 'uid:1000'].sort())
  assert.equal(disk.includes('com.first.app'), true)
  await config.write()
  assert.deepEqual(disk.sort(), ['com.second.app', 'com.concurrent.app', 'uid:1000'].sort())
})

test('a failed queued write retains new choices and retries against the last confirmed baseline', async () => {
  const { ConfigOhMyKeyMint } = modules(false)('config_ohmykeymint')
  let disk = ['com.old.app']
  let reject
  let calls = 0
  const config = new ConfigOhMyKeyMint({
    async getScoop() { return [...disk] },
    async updateScoop(added, removed) {
      if (++calls === 1) await new Promise((_, fail) => { reject = fail })
      disk = [...new Set([...disk.filter(target => !removed.includes(target)), ...added])]
      return [...disk]
    },
  })
  await config.read()
  config.set('target', ['com.first.app'])
  const pending = config.write()
  config.set('target', ['com.final.app'])
  reject(new Error('write failed'))
  await assert.rejects(pending, /write failed/)
  assert.deepEqual([...config.get('target')], ['com.final.app'])
  await config.write()
  assert.deepEqual(disk, ['com.final.app'])
})

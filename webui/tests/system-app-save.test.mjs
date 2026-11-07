import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

function handler(file, name, globals, prefix = '') {
  const source = readFileSync(new URL(`../src/vue/${file}`, import.meta.url), 'utf8')
    .split('<script setup lang="ts">')[1].split('</script>')[0]
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name)
  assert.ok(declaration, `Missing ${name}`)
  const javascript = ts.transpileModule(`${prefix}\n${declaration.getText(ast)}\n${name}`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText
  return vm.runInNewContext(javascript, globals)
}

function harness(writer = async () => {}) {
  let writes = 0
  const selected = new Set()
  const messages = []
  const targetsLoading = { value: false }
  const targetsSaving = { value: false }
  const targetsSaveError = { value: false }
  const snapshot = { value: null }
  const config = { isWritable: true }
  const appList = {
    setTargetSelected(entry, enabled) { enabled ? selected.add(entry.packageName) : selected.delete(entry.packageName) },
    async selectRecommended() { selected.add('com.example.recommended') },
    deselectAll() { selected.clear() },
    async save() { writes++; await writer([...selected]) },
    getSnapshot() { return { selected: [...selected] } },
  }
  const saveSelection = handler('App.vue', 'saveTargets', {
    targetsLoading, targetsSaving, targetsSaveError, config, appList, snapshot,
    afterPaint: async () => {},
    notify: (...values) => messages.push(values),
    i18n: { t: value => value }, console: { error() {} },
  }, 'let targetsSavePromise = null; let targetsSaveRequested = false;')
  const globals = {
    props: { appList, saveSelection, loading: false, applyEnabled: true },
    menuOpen: { value: false }, selectingRecommended: { value: false },
    systemSheetOpen: { value: true }, console: { error() {} },
  }
  return {
    ...globals, config, selected, messages, snapshot, targetsLoading, targetsSaving, targetsSaveError,
    saveSelection,
    toggle: handler('TargetsView.vue', 'setSelected', globals),
    recommended: handler('TargetsView.vue', 'selectRecommended', globals),
    deselect: handler('TargetsView.vue', 'deselectAll', globals),
    close: handler('TargetsView.vue', 'closeSystemApps', globals),
    get writes() { return writes },
  }
}

test('ordinary and system app toggles automatically request persistence', async () => {
  const state = harness()
  state.toggle({ packageName: 'com.example.app' }, true)
  state.toggle({ packageName: 'com.example.system' }, true)
  assert.equal(await state.saveSelection(), true)
  assert.equal(state.writes, 1)
  assert.deepEqual([...state.snapshot.value.selected].sort(), ['com.example.app', 'com.example.system'])
  state.toggle({ packageName: 'com.example.system' }, false)
  await state.saveSelection()
  assert.deepEqual([...state.snapshot.value.selected], ['com.example.app'])
})

test('rapid toggles are serialized, retain latest intent and finish after sheet closes', async () => {
  const waiting = []
  const saved = []
  let active = 0
  const state = harness(value => new Promise(resolve => {
    assert.equal(++active, 1, 'writes must never overlap')
    waiting.push(() => { saved.push(value); active--; resolve() })
  }))
  state.toggle({ packageName: 'com.example.first' }, true)
  const drain = state.saveSelection()
  await new Promise(resolve => setImmediate(resolve))
  state.toggle({ packageName: 'com.example.second' }, true)
  state.toggle({ packageName: 'com.example.first' }, false)
  state.close()
  assert.equal(state.systemSheetOpen.value, false)
  assert.equal(state.targetsSaving.value, true)
  waiting.shift()()
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(state.writes, 2)
  waiting.shift()()
  assert.equal(await drain, true)
  assert.deepEqual(saved.map(value => [...value]), [['com.example.first'], ['com.example.second']])
  assert.equal(state.targetsSaving.value, false)
})

test('failed autosave reports unsaved state, retains choices and retries without another toggle', async () => {
  let fail = true
  const state = harness(async () => { if (fail) throw new Error('write failed') })
  state.toggle({ packageName: 'com.example.app' }, true)
  assert.equal(await state.saveSelection(), false)
  assert.equal(state.targetsSaveError.value, true)
  assert.equal(state.targetsSaving.value, false)
  assert.equal(state.selected.has('com.example.app'), true)
  assert.equal(state.messages[0][0], 'prompt_save_error')
  fail = false
  assert.equal(await state.saveSelection(), true)
  assert.equal(state.targetsSaveError.value, false)
  assert.deepEqual([...state.snapshot.value.selected], ['com.example.app'])
})

test('recommended selection and deselect all automatically save', async () => {
  const state = harness()
  await state.recommended()
  assert.equal(state.writes, 1)
  assert.deepEqual([...state.snapshot.value.selected], ['com.example.recommended'])
  state.deselect()
  await state.saveSelection()
  assert.deepEqual([...state.snapshot.value.selected], [])
})

test('loading and read-only states reject checkbox mutations and autosaves', async () => {
  for (const guard of ['loading', 'applyEnabled']) {
    const state = harness()
    state.props[guard] = guard === 'loading'
    state.toggle({ packageName: 'com.example.app' }, true)
    assert.equal(state.selected.size, 0)
    assert.equal(state.writes, 0)
  }
  const state = harness()
  state.config.isWritable = false
  assert.equal(await state.saveSelection(), false)
  state.config.isWritable = true
  state.targetsLoading.value = true
  assert.equal(await state.saveSelection(), false)
  assert.equal(state.writes, 0)
})

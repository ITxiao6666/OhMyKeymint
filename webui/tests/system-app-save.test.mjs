import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

// Execute the actual SFC handlers with a delayed configuration writer. No
// Android commands or mocked filesystem persistence are used in these tests.
function handler(file, name, globals) {
  const source = readFileSync(new URL(`../src/vue/${file}`, import.meta.url), 'utf8')
    .split('<script setup lang="ts">')[1].split('</script>')[0]
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name)
  assert.ok(declaration, `Missing ${name}`)
  const javascript = ts.transpileModule(declaration.getText(ast), {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText
  return vm.runInNewContext(`${javascript}\n${name}`, globals)
}

function harness(writer = async () => {}) {
  let writes = 0
  let selections = 0
  let saved = false
  const messages = []
  const targetsLoading = { value: false }
  const snapshot = { value: null }
  const appList = {
    applySystemAppSelection(values) { selections++; assert.deepEqual([...values], ['com.example.system@0']) },
    async save() { writes++; await writer(); saved = true },
    getSnapshot() { return { saved } },
  }
  const saveSelection = handler('App.vue', 'saveTargets', {
    targetsLoading, appList, snapshot,
    afterPaint: async () => {},
    notify: (...values) => messages.push(values),
    i18n: { t: value => value },
    console: { error() {} },
  })
  const globals = {
    props: { appList, saveSelection, loading: false, applyEnabled: true },
    systemSaving: { value: false },
    systemSelection: { value: new Set(['com.example.system@0']) },
    systemSheetOpen: { value: true },
  }
  return {
    ...globals, snapshot, messages,
    save: handler('TargetsView.vue', 'saveSystemApps', globals),
    close: handler('TargetsView.vue', 'closeSystemApps', globals),
    get writes() { return writes },
    get selections() { return selections },
  }
}

test('system Save persists through the parent writer without a second checkmark', async () => {
  const state = harness()
  await state.save()
  assert.equal(state.writes, 1)
  assert.equal(state.selections, 1)
  assert.equal(state.snapshot.value.saved, true)
  assert.equal(state.systemSheetOpen.value, false)
  assert.equal(state.messages[0][0], 'prompt_saved_target')
})

test('pending write keeps the sheet open and blocks dismissal and repeat Save', async () => {
  let finish
  const state = harness(() => new Promise(resolve => { finish = resolve }))
  const saving = state.save()
  await Promise.resolve()
  await Promise.resolve()
  assert.equal(state.systemSaving.value, true)
  assert.equal(state.systemSheetOpen.value, true)
  state.close()
  await state.save()
  assert.equal(state.writes, 1)
  assert.equal(state.selections, 1)
  assert.equal(state.systemSheetOpen.value, true)
  finish()
  await saving
  assert.equal(state.systemSaving.value, false)
  assert.equal(state.systemSheetOpen.value, false)
})

test('failed write reports failure, retains the sheet and permits retry', async () => {
  let fail = true
  const state = harness(async () => { if (fail) throw new Error('write failed') })
  await state.save()
  assert.equal(state.systemSheetOpen.value, true)
  assert.equal(state.systemSaving.value, false)
  assert.equal(state.messages[0][0], 'prompt_save_error')
  assert.equal(state.snapshot.value, null)
  fail = false
  await state.save()
  assert.equal(state.systemSheetOpen.value, false)
  assert.equal(state.snapshot.value.saved, true)
})

test('unloaded or read-only configuration cannot be saved', async () => {
  for (const guard of ['loading', 'applyEnabled']) {
    const state = harness()
    state.props[guard] = guard === 'loading'
    await state.save()
    assert.equal(state.writes, 0)
    assert.equal(state.selections, 0)
    assert.equal(state.systemSheetOpen.value, true)
  }
})

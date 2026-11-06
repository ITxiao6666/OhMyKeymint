import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

const source = readFileSync(new URL('../src/vue/SoterIdentityDialog.vue', import.meta.url), 'utf8')
  .split('<script setup lang="ts">')[1].split('</script>')[0]
const ast = ts.createSourceFile('SoterIdentityDialog.vue', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)

function compile(text, globals, expression = false) {
  const code = ts.transpileModule(expression ? `(${text})` : text, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText
  return vm.runInNewContext(code, globals)
}

function computedValue(name, globals) {
  const declaration = ast.statements.filter(ts.isVariableStatement)
    .flatMap(statement => [...statement.declarationList.declarations])
    .find(node => node.name.getText(ast) === name)
  return compile(declaration.initializer.getText(ast), {
    computed: callback => ({ get value() { return callback() } }), ...globals,
  }, true)
}

test('bulk confirmation only counts targets without existing assignments', () => {
  const state = { value: { apps: { 'com.existing@0': { identity: 'other', cpu_id: 'override' } } } }
  const pending = computedValue('batchPending', {
    props: { batchTargets: ['com.existing@0', 'com.new@0', 'com.system@10'] }, state,
  })
  assert.deepEqual([...pending.value], ['com.new@0', 'com.system@10'])
  assert.equal(state.value.apps['com.existing@0'].identity, 'other')
})

test('bulk submit waits for persistence and keeps dialog open after a failure', async () => {
  const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'change')
  const state = { value: { enabled: false, identities: [], apps: {} } }
  const busy = { value: false }
  const error = { value: '' }
  let fail = true
  let closeCount = 0
  let received
  const code = ts.transpileModule(`${declaration.getText(ast)}\nchange`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText
  const change = vm.runInNewContext(code, {
    state, busy, error, pendingDelete: { value: null },
    isDev: () => false, afterPaint: async () => {},
    requestClose: () => { closeCount++ },
    props: { cli: { async changeSoterLocal(value) {
      received = value
      assert.equal(busy.value, true)
      if (fail) throw new Error('identity was deleted')
      return { ...state.value, apps: { 'com.new@0': { identity: value.identity, cpu_id: '' } } }
    } } },
  })
  const request = { action: 'apps', targets: ['com.new@0'], identity: 'selected' }
  await change(request)
  assert.equal(received, request)
  assert.equal(closeCount, 0)
  assert.ok(error.value.includes('identity was deleted'))
  assert.equal(busy.value, false)
  fail = false
  await change(request)
  assert.equal(closeCount, 1)
  assert.equal(state.value.enabled, false)
  assert.equal(state.value.apps['com.new@0'].identity, 'selected')
})

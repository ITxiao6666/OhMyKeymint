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

function release({ distance, velocity = 0, height, allowDismiss = true, elapsed = 4000 }) {
  const events = []
  const finish = handler('StableBottomSheet.vue', 'finish', {
    pointer: 7,
    distance,
    velocity,
    startedAt: 0,
    props: { allowDismiss },
    inner: { value: { offsetHeight: height } },
    performance: { now: () => elapsed },
    move() {},
    close() { events.push('close') },
    reset() { events.push('reset') },
  })
  finish({ pointerId: 7, type: 'pointerup', clientY: 0 })
  return events
}

test('a short slow drag below the scaled threshold springs back', () => {
  assert.deepEqual(release({ distance: 120, height: 600 }), ['reset'])
})

test('a drag past the threshold dismisses the sheet', () => {
  assert.deepEqual(release({ distance: 160, height: 600 }), ['close'])
})

test('a short sheet scales its threshold down instead of becoming undismissable', () => {
  // 25% of a 300px panel is 75px, so a 100px drag is enough.
  assert.deepEqual(release({ distance: 100, height: 300 }), ['close'])
  assert.deepEqual(release({ distance: 60, height: 300 }), ['reset'])
})

test('a fast flick dismisses even below the distance threshold', () => {
  // Sparse samples leave velocity at zero; the average gesture speed covers it.
  assert.deepEqual(release({ distance: 40, velocity: 0, elapsed: 40 }), ['close'])
  assert.deepEqual(release({ distance: 40, velocity: 0.9, elapsed: 4000 }), ['close'])
})

test('a slow short drag is not treated as a flick', () => {
  assert.deepEqual(release({ distance: 40, velocity: 0, elapsed: 4000 }), ['reset'])
})

test('a panel that may not be dismissed always springs back', () => {
  assert.deepEqual(release({ distance: 400, height: 600, allowDismiss: false }), ['reset'])
})

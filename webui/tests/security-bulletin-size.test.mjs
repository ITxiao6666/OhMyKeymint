import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

function declaration(file, name, globals) {
  const source = readFileSync(new URL(`../src/${file}`, import.meta.url), 'utf8')
  const ast = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const node = ast.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === name)
  assert.ok(node, `Missing ${name}`)
  const javascript = ts.transpileModule(`${node.getText(ast)}\n${name}`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText
  return vm.runInNewContext(javascript, globals)
}

const utf8ByteLength = declaration('security_patch.ts', 'utf8ByteLength', {})

test('ASCII, two-byte, three-byte and astral characters count their UTF-8 bytes', () => {
  assert.equal(utf8ByteLength(''), 0)
  assert.equal(utf8ByteLength('bulletin'), 8)
  // U+00E9 and U+4E2D need two and three bytes respectively.
  assert.equal(utf8ByteLength('é'), 2)
  assert.equal(utf8ByteLength('中'), 3)
  // A surrogate pair encodes to four bytes; a lone surrogate stays three.
  assert.equal(utf8ByteLength('🔒'), 4)
  assert.equal(utf8ByteLength('\ud800'), 3)
  assert.equal(utf8ByteLength('安全补丁级别 2026-11-05'), 6 * 3 + 1 + 10)
})

test('the bulletin size limit measures bytes rather than code units', () => {
  // 4 bytes per emoji: 600k of them are 2.4 MB of UTF-8 but only 1.2M code units,
  // so a code-unit check would wrongly accept this payload.
  const payload = 'a'.repeat(2 * 1024 * 1024 - 4) + '🔒'
  assert.equal(utf8ByteLength(payload), 2 * 1024 * 1024)
  assert.ok(payload.length < 2 * 1024 * 1024)
})

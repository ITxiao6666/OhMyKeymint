import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

const source = readFileSync(new URL('../src/cli.ts', import.meta.url), 'utf8')
const ast = ts.createSourceFile('cli.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
const cli = ast.statements.find(node => ts.isClassDeclaration(node) && node.name.text === 'Cli')
const method = cli.members.find(node => node.name?.getText(ast) === 'issueRkpKeybox')
const encoders = ast.statements.filter(node => ts.isFunctionDeclaration(node)
  && ['encodeBase64Bytes', 'encodeBase64Utf8'].includes(node.name?.text))

function harness() {
  const calls = []
  const code = `${encoders.map(node => node.getText(ast)).join('\n')}
    class TestCli {
      async #getHelperPaths() { return { keymint: '/module/keymint' } }
      async #run(command, args) { calls.push({ command, args }); return '{}' }
      ${method.getText(ast)}
    }
    new TestCli()`
  const javascript = ts.transpileModule(code, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText
  const client = vm.runInNewContext(javascript, {
    TextEncoder,
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    calls,
    MAX_RKP_ISSUED_JSON_BYTES: 512 * 1024,
    parseCanonicalJson: JSON.parse,
    parseRkpIssuedArtifact: value => value,
  })
  return { calls, client }
}

test('RKP fingerprint policy uses one exact command with opt-in CSR metadata', async () => {
  const { client, calls } = harness()
  await client.issueRkpKeybox()
  assert.deepEqual([...calls[0].args], ['--webui-rkp-issue', '--confirm-issuance', 'auto'])
  const fingerprint = 'source/device/build:16/构建/release-keys'
  await client.issueRkpKeybox('v1-native', true, `  ${fingerprint}  `)
  assert.deepEqual([...calls[1].args], [
    '--webui-rkp-issue', '--confirm-issuance', 'v1-native', '--include-fingerprint',
    '--fingerprint-base64', Buffer.from(fingerprint, 'utf8').toString('base64'),
  ])
  await client.issueRkpKeybox('v2', false, fingerprint)
  assert.equal(calls[2].args.includes('--include-fingerprint'), false)
  assert.equal(calls[2].args.at(-1), Buffer.from(fingerprint, 'utf8').toString('base64'))
})

test('invalid fingerprint arguments never invoke an Android helper', async () => {
  const { client, calls } = harness()
  for (const fingerprint of ['a\nb', 'source\u0085build', 'x'.repeat(1025), '界'.repeat(342)]) {
    await assert.rejects(client.issueRkpKeybox('auto', true, fingerprint), /Invalid RKP build fingerprint/)
  }
  await assert.rejects(client.issueRkpKeybox('unsupported', true, ''), /Invalid RKP protocol/)
  assert.equal(calls.length, 0)
})

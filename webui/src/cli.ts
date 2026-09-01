import { spawn } from 'kernelsu-alt'
import { normalizePackageNames } from './package_name'
import {
  ANDROID_SECURITY_BULLETIN_MIRROR_URL,
  ANDROID_SECURITY_BULLETIN_URL,
  isOfficialSecurityBulletinUrl,
  isSecurityPatchDate,
} from './security_patch'

const INJECT_BIN = '/data/adb/modules/oh_my_keymint/libs/arm64-v8a/inject'
const KEYMINT_BIN = '/data/adb/modules/oh_my_keymint/libs/arm64-v8a/keymint'
const KEYBOX_BASE64_CHUNK_BYTES = 48 * 1024
const MAX_BULLETIN_BYTES = 2 * 1024 * 1024
const CURL_FINAL_URL_MARKER = 'OMK_FINAL_URL:'

export const MAX_KEYBOX_XML_BYTES = 64 * 1024

function encodeBase64Bytes(bytes: Uint8Array): string {
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return btoa(binary)
}

function encodeBase64Utf8(value: string): string {
  return encodeBase64Bytes(new TextEncoder().encode(value))
}

export class Cli {
  async getScoop(): Promise<string[]> {
    const output = await this.#runInject(['--webui-get-scoop'])
    let parsed: unknown
    try {
      parsed = JSON.parse(output)
    } catch {
      throw new Error('OMK returned an invalid package list')
    }
    return normalizePackageNames(parsed)
  }

  async setScoop(packages: string[]): Promise<void> {
    const normalized = normalizePackageNames(packages)
    const payload = encodeBase64Utf8(JSON.stringify(normalized))
    await this.#runInject(['--webui-set-scoop', payload])
  }

  async installKeybox(contents: Uint8Array): Promise<void> {
    if (contents.byteLength > MAX_KEYBOX_XML_BYTES) {
      throw new Error(`keybox.xml exceeds the ${MAX_KEYBOX_XML_BYTES} byte limit`)
    }

    const payload = encodeBase64Bytes(contents)
    const chunks: string[] = []
    for (let offset = 0; offset < payload.length; offset += KEYBOX_BASE64_CHUNK_BYTES) {
      chunks.push(payload.slice(offset, offset + KEYBOX_BASE64_CHUNK_BYTES))
    }
    await this.#run(KEYMINT_BIN, ['--webui-install-keybox', ...chunks])
  }

  async syncSecurityPatch(date: string): Promise<void> {
    if (!isSecurityPatchDate(date)) {
      throw new Error('Invalid security-patch date')
    }

    const output = await this.#run(KEYMINT_BIN, ['--webui-sync-security-patch', date])
    if (output !== date) {
      throw new Error('OMK returned an unexpected security-patch date')
    }
  }

  async restoreDefaultSecurityPatch(): Promise<void> {
    const output = await this.#run(KEYMINT_BIN, ['--webui-sync-security-patch', 'auto'])
    if (output !== 'auto') {
      throw new Error('OMK returned an unexpected security-patch mode')
    }
  }

  async fetchSecurityBulletin(): Promise<string> {
    let lastError: Error | null = null
    for (const url of [ANDROID_SECURITY_BULLETIN_URL, ANDROID_SECURITY_BULLETIN_MIRROR_URL]) {
      try {
        const output = await this.#run(
          'curl',
          [
            '--fail', '--silent', '--show-error', '--location',
            '--connect-timeout', '10', '--max-time', '15', '--max-redirs', '3',
            '--max-filesize', String(MAX_BULLETIN_BYTES),
            '--proto', '=https', '--proto-redir', '=https',
            '--write-out', `${CURL_FINAL_URL_MARKER}%{url_effective}`,
            url,
          ],
          MAX_BULLETIN_BYTES + 1024,
        )
        return this.#validatedCurlBody(output)
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))
      }
    }
    throw new Error(`Unable to download the Android Security Bulletin with curl: ${lastError?.message ?? 'curl is unavailable'}`)
  }

  #validatedCurlBody(output: string): string {
    const marker = output.lastIndexOf(CURL_FINAL_URL_MARKER)
    if (marker < 0) throw new Error('curl did not report the final bulletin URL')

    const finalUrl = output.slice(marker + CURL_FINAL_URL_MARKER.length).trim()
    if (!isOfficialSecurityBulletinUrl(finalUrl)) {
      throw new Error('curl was redirected outside the official bulletin page')
    }
    return output.slice(0, marker)
  }

  #runInject(args: string[]): Promise<string> {
    return this.#run(INJECT_BIN, args)
  }

  #run(binary: string, args: string[], maxOutputBytes = Number.POSITIVE_INFINITY): Promise<string> {
    return new Promise((resolve, reject) => {
      let stdout = ''
      let stderr = ''
      let stdoutBytes = 0
      let stderrBytes = 0
      let outputTooLarge = false
      let settled = false
      const process = spawn(binary, args)

      process.stdout.on('data', (chunk: string) => {
        if (outputTooLarge) return
        stdoutBytes += new TextEncoder().encode(chunk).byteLength
        if (stdoutBytes > maxOutputBytes) {
          outputTooLarge = true
          return
        }
        stdout += chunk
      })
      process.stderr.on('data', (chunk: string) => {
        if (stderrBytes >= 8192) return
        const remaining = 8192 - stderrBytes
        const encoded = new TextEncoder().encode(chunk)
        stderrBytes += encoded.byteLength
        stderr += new TextDecoder().decode(encoded.subarray(0, remaining))
      })
      process.on('exit', (code: number | null) => {
        if (settled) return
        settled = true
        if (outputTooLarge) {
          reject(new Error('command output exceeds the configured limit'))
        } else if (code === 0) {
          resolve(stdout.trim())
        } else {
          reject(new Error(stderr.trim() || `OMK helper exited with code ${code ?? 'unknown'}`))
        }
      })
      process.on('error', (error: Error) => {
        if (settled) return
        settled = true
        reject(new Error(`Unable to run the OMK helper: ${error.message}`))
      })
    })
  }
}

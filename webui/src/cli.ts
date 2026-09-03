import { exec, spawn } from 'kernelsu-alt'
import { normalizePackageNames } from './package_name'
import {
  ANDROID_SECURITY_BULLETIN_MIRROR_URL,
  ANDROID_SECURITY_BULLETIN_URL,
  isSecurityPatchDate,
} from './security_patch'

const MODULE_ROOT = '/data/adb/modules/oh_my_keymint'
const HOT_UPDATE_ROOT = '/data/adb/omk'
const SUPPORTED_ABIS = ['arm64-v8a', 'x86_64'] as const
type SupportedAbi = typeof SUPPORTED_ABIS[number]
type HelperPaths = { abi: SupportedAbi, inject: string, keymint: string }
const KEYBOX_BASE64_CHUNK_BYTES = 48 * 1024
const MAX_BULLETIN_BYTES = 2 * 1024 * 1024
const MAX_PIF_CATALOG_BYTES = 64 * 1024
const MAX_PIF_STATE_BYTES = 2 * 1024
const MAX_PIF_DEVICES = 64
const MAX_PIF_MODEL_LENGTH = 128
const MAX_PIF_PRODUCT_LENGTH = 128
const MAX_PIF_FINGERPRINT_LENGTH = 1024
const PIF_PRODUCT_RE = /^[a-z0-9][a-z0-9_]*$/

export const MAX_KEYBOX_XML_BYTES = 64 * 1024

export interface PifDevice {
  model: string
  product: string
}

export interface EnabledPifFingerprintState {
  enabled: true
  model: string
  product: string
  fingerprint: string
  security_patch: string
}

export type PifFingerprintState = {
  enabled: false
} | EnabledPifFingerprintState

function parseCanonicalJson(output: string, description: string): unknown {
  let parsed: unknown
  try {
    parsed = JSON.parse(output)
  } catch {
    throw new Error(`OMK returned invalid ${description}`)
  }
  if (JSON.stringify(parsed) !== output) {
    throw new Error(`OMK returned non-canonical ${description}`)
  }
  return parsed
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(value)
  return keys.length === allowed.length && keys.every((key, index) => key === allowed[index])
}

function isSafeText(value: unknown, maxLength: number): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= maxLength
    && value.trim() === value
    && !/[\u0000-\u001f\u007f]/.test(value)
}

function isPifProduct(value: unknown): value is string {
  return isSafeText(value, MAX_PIF_PRODUCT_LENGTH) && PIF_PRODUCT_RE.test(value)
}

function parsePifDevice(value: unknown): PifDevice {
  if (!isRecord(value)
      || !hasOnlyKeys(value, ['model', 'product'])
      || !isSafeText(value.model, MAX_PIF_MODEL_LENGTH)
      || !isPifProduct(value.product)) {
    throw new Error('OMK returned an invalid PIF device')
  }
  return { model: value.model, product: value.product }
}

function parsePifState(output: string): PifFingerprintState {
  const parsed = parseCanonicalJson(output, 'PIF fingerprint state')
  if (!isRecord(parsed) || typeof parsed.enabled !== 'boolean') {
    throw new Error('OMK returned an invalid PIF fingerprint state')
  }
  if (!parsed.enabled) {
    if (!hasOnlyKeys(parsed, ['enabled'])) {
      throw new Error('OMK returned an invalid disabled PIF fingerprint state')
    }
    return { enabled: false }
  }
  if (!hasOnlyKeys(parsed, ['enabled', 'model', 'product', 'fingerprint', 'security_patch'])
      || !isSafeText(parsed.model, MAX_PIF_MODEL_LENGTH)
      || !isPifProduct(parsed.product)
      || !isSafeText(parsed.fingerprint, MAX_PIF_FINGERPRINT_LENGTH)
      || !isSafeText(parsed.security_patch, 10)
      || !isSecurityPatchDate(parsed.security_patch)) {
    throw new Error('OMK returned an invalid enabled PIF fingerprint state')
  }
  return {
    enabled: true,
    model: parsed.model,
    product: parsed.product,
    fingerprint: parsed.fingerprint,
    security_patch: parsed.security_patch,
  }
}

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

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function normalizeAbiToken(value: string): SupportedAbi | null {
  switch (value.trim()) {
    case 'arm64-v8a':
    case 'aarch64':
      return 'arm64-v8a'
    case 'x86_64':
    case 'amd64':
      return 'x86_64'
    default:
      return null
  }
}

function parseSupportedAbi(output: string): SupportedAbi | null {
  const tokens = output.split(/[\s,]+/).filter(Boolean)
  for (const token of tokens) {
    const abi = normalizeAbiToken(token)
    if (abi !== null) return abi
  }
  return null
}

export class Cli {
  #helperPaths: Promise<HelperPaths> | null = null

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
    const { keymint } = await this.#getHelperPaths()
    await this.#run(keymint, ['--webui-install-keybox', ...chunks])
  }

  async syncSecurityPatch(date: string): Promise<string> {
    if (!isSecurityPatchDate(date)) {
      throw new Error('Invalid security-patch date')
    }

    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-sync-security-patch', date])
    const firstDayFallback = date.endsWith('-05') ? `${date.slice(0, 8)}01` : null
    if (output !== date && output !== firstDayFallback) {
      throw new Error('OMK returned an unexpected security-patch date')
    }
    return output
  }

  async restoreDefaultSecurityPatch(): Promise<void> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(keymint, ['--webui-sync-security-patch', 'auto'])
    if (output !== 'auto') {
      throw new Error('OMK returned an unexpected security-patch mode')
    }
  }

  async fetchSecurityBulletin(): Promise<string> {
    let lastError: Error | null = null
    for (const url of [ANDROID_SECURITY_BULLETIN_URL, ANDROID_SECURITY_BULLETIN_MIRROR_URL]) {
      try {
        const { keymint } = await this.#getHelperPaths()
        return await this.#run(
          keymint,
          ['--webui-fetch-security-bulletin', url],
          MAX_BULLETIN_BYTES + 1024,
        )
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))
      }
    }
    throw new Error(`Unable to download the Android Security Bulletin: ${lastError?.message ?? 'network request failed'}`)
  }

  async getPifFingerprintState(): Promise<PifFingerprintState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-get-pif-fingerprint-state'],
      MAX_PIF_STATE_BYTES,
    )
    return parsePifState(output)
  }

  async listPifDevices(): Promise<PifDevice[]> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-list-pif-devices'],
      MAX_PIF_CATALOG_BYTES,
    )
    const parsed = parseCanonicalJson(output, 'PIF device catalog')
    if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > MAX_PIF_DEVICES) {
      throw new Error('OMK returned an invalid PIF device catalog')
    }

    const devices = parsed.map(parsePifDevice)
    if (new Set(devices.map(device => device.product)).size !== devices.length) {
      throw new Error('OMK returned duplicate PIF products')
    }
    return devices
  }

  async applyPifFingerprint(product: string): Promise<EnabledPifFingerprintState> {
    if (!isPifProduct(product)) throw new Error('Invalid PIF product')
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-apply-pif-fingerprint', product],
      MAX_PIF_STATE_BYTES,
    )
    const state = parsePifState(output)
    if (!state.enabled || state.product !== product) {
      throw new Error('OMK returned an unexpected PIF fingerprint state')
    }
    return state
  }

  async disablePifFingerprint(): Promise<PifFingerprintState> {
    const { keymint } = await this.#getHelperPaths()
    const output = await this.#run(
      keymint,
      ['--webui-disable-pif-fingerprint'],
      MAX_PIF_STATE_BYTES,
    )
    const state = parsePifState(output)
    if (state.enabled) throw new Error('OMK did not disable PIF fingerprint spoofing')
    return state
  }

  async #runInject(args: string[]): Promise<string> {
    const { inject } = await this.#getHelperPaths()
    return this.#run(inject, args)
  }

  async #getHelperPaths(): Promise<HelperPaths> {
    if (this.#helperPaths !== null) return this.#helperPaths

    const pending = this.#detectHelperPaths()
    this.#helperPaths = pending.catch(error => {
      this.#helperPaths = null
      throw error
    })
    return this.#helperPaths
  }

  async #detectHelperPaths(): Promise<HelperPaths> {
    let abiProbe: Awaited<ReturnType<typeof exec>>
    try {
      abiProbe = await exec(
        `/system/bin/sh -c ${shellQuote('/system/bin/getprop ro.product.cpu.abilist; /system/bin/getprop ro.product.cpu.abi; /system/bin/uname -m 2>/dev/null || :')}`,
      )
    } catch (error) {
      throw new Error(`Unable to detect the Android ABI: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (abiProbe.errno !== 0) {
      throw new Error(
        `Unable to detect the Android ABI: ${abiProbe.stderr.trim() || `shell exited with code ${abiProbe.errno}`}`,
      )
    }

    const abi = parseSupportedAbi(abiProbe.stdout)
    if (abi === null) {
      throw new Error('Unsupported Android ABI: OMK provides arm64-v8a and x86_64 binaries')
    }

    const roots = [HOT_UPDATE_ROOT, `${MODULE_ROOT}/libs/${abi}`]
    for (const root of roots) {
      const inject = `${root}/inject`
      const keymint = `${root}/keymint`
      const check = await exec(
        `/system/bin/sh -c ${shellQuote(`[ -x ${shellQuote(inject)} ] && [ -x ${shellQuote(keymint)} ]`)}`,
      )
      if (check.errno === 0) return { abi, inject, keymint }
    }

    throw new Error(`OMK ${abi} helper binaries are not installed`)
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

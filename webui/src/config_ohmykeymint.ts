import { Cli } from './cli'
import { Config } from './config'
import { isDev } from './utils/dev'
import { parseScoopTarget } from './package_name'

export class ConfigOhMyKeyMint extends Config {
  readonly #cli: Cli
  #loaded = false
  #savedTargets = new Set<string>()

  constructor(cli: Cli) {
    super()
    this.#cli = cli
  }

  override async read(): Promise<void> {
    this.#loaded = false
    if (isDev()) {
      this.set({
        target: [
          'io.github.vvb2060.keyattestation',
          'com.google.android.gms',
        ],
      })
      this.#savedTargets = new Set(this.get('target'))
      this.#loaded = true
      return
    }

    const target = await this.#cli.getScoop()
    this.set({ target })
    this.#savedTargets = new Set(target)
    this.#loaded = true
  }

  override async write(): Promise<void> {
    if (!this.#loaded) {
      throw new Error('Saving is disabled until the OMK package list is loaded')
    }
    // UI-managed package selection follows the upstream all-user format.
    // Preserve explicit UID rules; legacy package@user entries convert only
    // when the user explicitly saves, never merely by opening the picker.
    const packageTarget = (value: string): string => {
      const target = parseScoopTarget(value)
      if (!target) throw new Error('Invalid package selection')
      return target.kind === 'uid' ? target.target : target.packageName
    }
    const desired = new Set(this.get('target').map(packageTarget))
    const added = [...desired].filter(target => !this.#savedTargets.has(target))
    const removed = [...this.#savedTargets].filter(target => !desired.has(target))
    const saved = isDev() ? [...desired] : await this.#cli.updateScoop(added, removed)
    // Retain edits made while the bridge was writing its captured snapshot.
    const current = new Set(this.get('target').map(packageTarget))
    const merged = new Set(saved)
    for (const target of current) if (!desired.has(target)) merged.add(target)
    for (const target of desired) if (!current.has(target)) merged.delete(target)
    this.#savedTargets = new Set(saved)
    this.set({ target: [...merged] })
  }

  async refresh(): Promise<void> {
    if (!this.#loaded) return this.read()
    if (isDev()) return
    // Capture edits after the await: a slow refresh must not erase a new click.
    const latest = new Set(await this.#cli.getScoop())
    const desired = new Set(this.get('target'))
    const merged = new Set(latest)
    for (const target of desired) if (!this.#savedTargets.has(target)) merged.add(target)
    for (const target of this.#savedTargets) if (!desired.has(target)) merged.delete(target)
    this.#savedTargets = latest
    this.set({ target: [...merged] })
  }

  override get isWritable(): boolean {
    return this.#loaded
  }
}

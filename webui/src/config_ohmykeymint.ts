import { Cli } from './cli'
import { Config } from './config'
import { isDev } from './utils/dev'

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
    const desired = new Set(this.get('target'))
    const added = [...desired].filter(target => !this.#savedTargets.has(target))
    const removed = [...this.#savedTargets].filter(target => !desired.has(target))
    const saved = isDev() ? [...desired] : await this.#cli.updateScoop(added, removed)
    this.set({ target: saved })
    this.#savedTargets = new Set(saved)
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

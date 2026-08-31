import { Cli } from './cli'
import { Config } from './config'
import { isDev } from './utils/dev'

export class ConfigOhMyKeyMint extends Config {
  readonly #cli: Cli
  #loaded = false

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
      this.#loaded = true
      return
    }

    const target = await this.#cli.getScoop()
    this.set({ target })
    this.#loaded = true
  }

  override async write(): Promise<void> {
    if (!this.#loaded) {
      throw new Error('Saving is disabled until the OMK package list is loaded')
    }
    if (isDev()) return
    await this.#cli.setScoop(this.get('target'))
  }

  override get isWritable(): boolean {
    return this.#loaded
  }
}

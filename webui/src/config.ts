export interface ConfigData {
  target: string[]
}

export class Config {
  #data: ConfigData = { target: [] }

  async read(): Promise<void> {
    throw new Error('Config.read is not implemented')
  }

  async write(): Promise<void> {
    throw new Error('Config.write is not implemented')
  }

  get(): ConfigData
  get(section: 'target'): string[]
  get(section?: 'target'): ConfigData | string[] {
    return section === 'target' ? this.#data.target : this.#data
  }

  set(data: ConfigData): void
  set(section: 'target', value: string[]): void
  set(section: ConfigData | 'target', value?: string[]): void {
    if (typeof section === 'object') {
      this.#data = section
      return
    }
    this.#data.target = value ?? []
  }

  push(section: 'target', value: string): void {
    if (section === 'target') this.#data.target.push(value)
  }

  removeMatch(section: 'target', predicate: (value: string) => boolean): string[] {
    if (section !== 'target') return []
    const removed = this.#data.target.filter(predicate)
    this.#data.target = this.#data.target.filter(value => !predicate(value))
    return removed
  }

  get isWritable(): boolean {
    return false
  }
}

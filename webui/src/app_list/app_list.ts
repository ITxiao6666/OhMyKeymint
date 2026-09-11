import { getPackagesInfo, listPackages } from 'kernelsu-alt'
import type { PackagesInfo } from 'kernelsu-alt'
import type { Config } from '../config'
import { isValidPackageName } from '../package_name'
import { isDev } from '../utils/dev'

const DEFAULT_VISIBLE_SYSTEM_APPS = [
  'com.google.android.gsf',
  'com.google.android.gms',
  'com.android.vending',
] as const

const PACKAGE_INFO_BATCH_SIZE = 32

function afterPaint(): Promise<void> {
  return new Promise(resolve => {
    window.requestAnimationFrame(() => window.setTimeout(resolve, 0))
  })
}

function normalizeSearchQuery(query: string): string {
  return query.trim().toLocaleLowerCase()
}

export type SelectionFilter = 'all' | 'selected' | 'unselected'

export interface AppEntry {
  packageName: string
  appName: string
  isSystem: boolean
}

export interface SelectableAppEntry extends AppEntry {
  selected: boolean
}

export interface AppListSnapshot {
  revision: number
  entries: readonly AppEntry[]
  selectedPackages: readonly string[]
  selectedCount: number
  isWritable: boolean
}

export type AppListSubscriber = (snapshot: AppListSnapshot) => void

export class AppList {
  readonly #config: Config
  readonly #visibleSystemApps = new Set<string>(DEFAULT_VISIBLE_SYSTEM_APPS)
  readonly #packageInfoCache = new Map<string, PackagesInfo>()
  readonly #subscribers = new Set<AppListSubscriber>()
  #entries: AppEntry[] = []
  #revision = 0
  #fetchPromise: Promise<boolean> | null = null

  constructor(config: Config) {
    this.#config = config
  }

  get revision(): number {
    return this.#revision
  }

  get isWritable(): boolean {
    return this.#config.isWritable
  }

  getSnapshot(): AppListSnapshot {
    const selectedPackages = [...new Set(this.#config.get('target'))]
    return {
      revision: this.#revision,
      entries: [...this.#entries],
      selectedPackages,
      selectedCount: selectedPackages.length,
      isWritable: this.#config.isWritable,
    }
  }

  subscribe(subscriber: AppListSubscriber): () => void {
    this.#subscribers.add(subscriber)
    subscriber(this.getSnapshot())
    return () => this.#subscribers.delete(subscriber)
  }

  async fetch(): Promise<boolean> {
    if (this.#fetchPromise !== null) return this.#fetchPromise
    const request = this.#fetch()
    this.#fetchPromise = request
    try {
      return await request
    } finally {
      if (this.#fetchPromise === request) this.#fetchPromise = null
    }
  }

  getEntries(): readonly AppEntry[] {
    return [...this.#entries]
  }

  getTargetEntries(query = '', filter: SelectionFilter = 'all'): SelectableAppEntry[] {
    const selected = new Set(this.#config.get('target'))
    const normalizedQuery = normalizeSearchQuery(query)
    return this.#entries
      .filter(entry => !entry.isSystem || this.#visibleSystemApps.has(entry.packageName))
      .map(entry => ({ ...entry, selected: selected.has(entry.packageName) }))
      .filter(entry => this.#matches(entry, normalizedQuery, filter))
      .sort((left, right) => this.#compareEntries(left, right))
  }

  getSystemEntries(query = ''): SelectableAppEntry[] {
    const selected = new Set(this.#config.get('target'))
    const normalizedQuery = normalizeSearchQuery(query)
    return this.#entries
      .filter(entry => entry.isSystem)
      .map(entry => ({ ...entry, selected: selected.has(entry.packageName) }))
      .filter(entry => this.#matchesSearch(entry, normalizedQuery))
      .sort((left, right) => this.#compareEntries(left, right))
  }

  getSelectedPackages(): string[] {
    return [...new Set(this.#config.get('target'))]
  }

  getSelectedCount(): number {
    return this.getSelectedPackages().length
  }

  isSelected(packageName: string): boolean {
    return this.#config.get('target').includes(packageName)
  }

  setSelected(packageName: string, selected: boolean): void {
    if (!isValidPackageName(packageName)) return
    const targets = new Set(this.#config.get('target'))
    const changed = selected ? !targets.has(packageName) : targets.has(packageName)
    if (!changed) return

    if (selected) targets.add(packageName)
    else targets.delete(packageName)
    this.#config.set('target', [...targets])
    this.#emitChange()
  }

  toggleSelected(packageName: string): void {
    this.setSelected(packageName, !this.isSelected(packageName))
  }

  selectAll(): void {
    const targets = new Set(this.#config.get('target'))
    let changed = false
    for (const entry of this.getTargetEntries()) {
      if (targets.has(entry.packageName)) continue
      targets.add(entry.packageName)
      changed = true
    }
    if (!changed) return
    this.#config.set('target', [...targets])
    this.#emitChange()
  }

  deselectAll(): void {
    if (this.#config.get('target').length === 0) return
    this.#config.set('target', [])
    this.#emitChange()
  }

  applySystemAppSelection(checkedApps: readonly string[]): void {
    const installedSystemApps = new Set(
      this.#entries.filter(entry => entry.isSystem).map(entry => entry.packageName),
    )
    const checked = new Set(
      checkedApps.filter(packageName => (
        isValidPackageName(packageName) && installedSystemApps.has(packageName)
      )),
    )

    this.#visibleSystemApps.clear()
    for (const packageName of DEFAULT_VISIBLE_SYSTEM_APPS) {
      this.#visibleSystemApps.add(packageName)
    }
    for (const packageName of checked) this.#visibleSystemApps.add(packageName)

    const targets = new Set(this.#config.get('target'))
    for (const packageName of installedSystemApps) {
      if (checked.has(packageName)) targets.add(packageName)
      else targets.delete(packageName)
    }
    this.#config.set('target', [...targets])
    this.#emitChange()
  }

  syncSystemAppsWithConfig(): void {
    const targets = new Set(this.#config.get('target'))
    for (const entry of this.#entries) {
      if (entry.isSystem && targets.has(entry.packageName)) {
        this.#visibleSystemApps.add(entry.packageName)
      }
    }
    this.#emitChange()
  }

  async save(): Promise<void> {
    await this.#config.write()
  }

  async #fetch(): Promise<boolean> {
    if (isDev()) return this.#replaceEntries(this.#getDevEntries())

    // KernelSU package APIs cross a synchronous WebView bridge. Yield before
    // each call so the navigation and progress animations can reach the screen.
    await afterPaint()
    const rawPackages = await listPackages('all').catch(() => [])
    const packages = [...new Set(rawPackages.filter(isValidPackageName))].sort()
    const installedPackages = new Set(packages)

    for (const packageName of this.#packageInfoCache.keys()) {
      if (!installedPackages.has(packageName)) this.#packageInfoCache.delete(packageName)
    }

    const missingPackages = packages.filter(packageName => !this.#packageInfoCache.has(packageName))
    for (let offset = 0; offset < missingPackages.length; offset += PACKAGE_INFO_BATCH_SIZE) {
      await afterPaint()
      const batch = missingPackages.slice(offset, offset + PACKAGE_INFO_BATCH_SIZE)
      try {
        const infos = await getPackagesInfo(batch) as PackagesInfo[]
        for (const info of infos) {
          if (isValidPackageName(info.packageName) && installedPackages.has(info.packageName)) {
            this.#packageInfoCache.set(info.packageName, info)
          }
        }
      } catch {
        // Package names remain selectable when labels or metadata are unavailable.
      }
    }

    return this.#replaceEntries(packages.map(packageName => {
      const info = this.#packageInfoCache.get(packageName)
      return {
        packageName,
        appName: typeof info?.appLabel === 'string' && info.appLabel
          ? info.appLabel
          : packageName,
        isSystem: info?.isSystem ?? false,
      }
    }))
  }

  #replaceEntries(entries: AppEntry[]): boolean {
    const previousEntries = new Map(this.#entries.map(entry => [entry.packageName, entry]))
    const changed = entries.length !== this.#entries.length || entries.some(entry => {
      const previous = previousEntries.get(entry.packageName)
      return previous?.appName !== entry.appName || previous.isSystem !== entry.isSystem
    })
    if (!changed) return false

    this.#entries = entries
    const installedPackages = new Set(entries.map(entry => entry.packageName))
    for (const packageName of this.#visibleSystemApps) {
      if (!DEFAULT_VISIBLE_SYSTEM_APPS.includes(packageName as typeof DEFAULT_VISIBLE_SYSTEM_APPS[number])
        && !installedPackages.has(packageName)) {
        this.#visibleSystemApps.delete(packageName)
      }
    }
    this.#emitChange()
    return true
  }

  #matches(
    entry: SelectableAppEntry,
    normalizedQuery: string,
    filter: SelectionFilter,
  ): boolean {
    const selectionMatches = filter === 'all'
      || (filter === 'selected' && entry.selected)
      || (filter === 'unselected' && !entry.selected)
    return selectionMatches && this.#matchesSearch(entry, normalizedQuery)
  }

  #matchesSearch(entry: AppEntry, normalizedQuery: string): boolean {
    if (!normalizedQuery) return true
    return `${entry.appName}\n${entry.packageName}`.toLocaleLowerCase().includes(normalizedQuery)
  }

  #compareEntries(left: SelectableAppEntry, right: SelectableAppEntry): number {
    if (left.selected !== right.selected) return left.selected ? -1 : 1
    return left.appName.localeCompare(right.appName)
  }

  #emitChange(): void {
    this.#revision++
    const snapshot = this.getSnapshot()
    for (const subscriber of this.#subscribers) subscriber(snapshot)
  }

  #getDevEntries(): AppEntry[] {
    return [
      { packageName: 'io.github.vvb2060.keyattestation', appName: 'Key Attestation', isSystem: false },
      { packageName: 'com.example.app', appName: 'Example App', isSystem: false },
      { packageName: 'com.example.banking', appName: 'Banking App', isSystem: false },
      { packageName: 'com.google.android.gms', appName: 'Google Play services', isSystem: true },
      { packageName: 'com.android.vending', appName: 'Google Play Store', isSystem: true },
      { packageName: 'com.google.android.gsf', appName: 'Google Services Framework', isSystem: true },
    ]
  }
}

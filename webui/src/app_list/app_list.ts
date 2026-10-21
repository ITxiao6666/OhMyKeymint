import { exec, getPackagesInfo } from 'kernelsu-alt'
import type { PackagesInfo } from 'kernelsu-alt'
import type { Config } from '../config'
import { isValidPackageName, parseScoopTarget } from '../package_name'
import { isDev } from '../utils/dev'

const RECOMMENDED_SYSTEM_APPS = [
  'com.google.android.gsf',
  'com.google.android.gms',
  'com.android.vending',
] as const

const PACKAGE_INFO_BATCH_SIZE = 32

// Exact identifiers only: a name containing "root" is not evidence that an app
// is a root tool. Permission/category discovery below covers additional apps.
const ROOT_TOOL_PACKAGES = new Set([
  'me.weishu.kernelsu',
  'com.rifsxd.ksunext',
  'me.bmax.apatch',
  'com.topjohnwu.magisk',
  'io.github.huskydg.magisk',
  'eu.chainfire.supersu',
  'com.noshufou.android.su',
  'org.lsposed.manager',
  'de.robv.android.xposed.installer',
  'org.meowcat.edxposed.manager',
  'moe.shizuku.privileged.api',
  'rikka.sui',
  'com.tsng.hidemyapplist',
  'org.frknkrc44.hma_oss',
  'bin.mt.plus',
])

export function afterPaint(): Promise<void> {
  return new Promise(resolve => {
    window.requestAnimationFrame(() => window.setTimeout(resolve, 0))
  })
}

function normalizeSearchQuery(query: string): string {
  return query.trim().toLocaleLowerCase()
}

interface AndroidUser {
  userId: number
  current: boolean
}

async function queryAndroidUsers(): Promise<AndroidUser[]> {
  let currentUserId: number | null = null
  for (const command of ['am get-current-user', 'cmd activity get-current-user']) {
    try {
      const result = await exec(command)
      const value = result.stdout.trim()
      if (result.errno === 0 && /^\d+$/.test(value) && Number.isSafeInteger(Number(value))) {
        currentUserId = Number(value)
        break
      }
    } catch {
      // Try the alternate ActivityManager command.
    }
  }
  // A root WebUI bridge can belong to a different user than the foreground
  // Android session. Never label a bridge package snapshot as user 0 or as an
  // arbitrary profile when ActivityManager cannot identify the current user.
  if (currentUserId === null) throw new Error('Unable to identify the current Android user')

  const userIds = new Set([currentUserId])
  for (const command of ['cmd user list', 'pm list users']) {
    try {
      const result = await exec(command)
      if (result.errno !== 0) continue
      for (const match of result.stdout.matchAll(/UserInfo\{(\d+):/g)) {
        const userId = Number(match[1])
        if (Number.isSafeInteger(userId)) userIds.add(userId)
      }
      if (userIds.size > 1 || /UserInfo\{/.test(result.stdout)) break
    } catch {
      // Listing profiles is best effort; the confirmed current user remains.
    }
  }
  return [...userIds]
    .sort((left, right) => left === currentUserId ? -1 : right === currentUserId ? 1 : left - right)
    .map(userId => ({ userId, current: userId === currentUserId }))
}

async function queryInstalledPackages(
  userId: number,
  type: 'all' | 'user' | 'system' = 'all',
): Promise<string[]> {
  // ksu.listPackages() can retain the package-manager snapshot from the
  // WebView process. Query Android's package manager directly on every fetch
  // so apps installed while the WebUI is open appear without a cold start.
  const filter = type === 'user' ? ' -3' : type === 'system' ? ' -s' : ''
  const commands = [
    `/system/bin/pm list packages --user ${userId}${filter}`,
    `cmd package list packages --user ${userId}${filter}`,
  ]
  for (const command of commands) {
    try {
      const result = await exec(command)
      if (result.errno !== 0) continue
      const packages = result.stdout
        .split(/\r?\n/)
        .map(line => line.trim())
        .filter(line => line.startsWith('package:'))
        .map(line => line.slice('package:'.length))
        .filter(isValidPackageName)
      if (packages.length > 0 || result.stdout.trim() === '') return [...new Set(packages)].sort()
    } catch {
      // Try the alternate package-manager command.
    }
  }

  // listPackages/getPackagesInfo have no user argument. Falling back to that
  // snapshot would misattribute apps to the requested profile.
  throw new Error(`Unable to list installed packages for Android user ${userId}`)
}

export type SelectionFilter = 'all' | 'selected' | 'unselected'

/**
 * The WebUI keeps the Android user alongside a package name so entries from
 * different profiles can be selected using the injector's package@user scoop
 * rules. Bare package entries still apply to every Android user.
 */
export interface PackageUserTarget {
  packageName: string
  userId: number
  targetKey: string
}

export function formatPackageUserTarget(packageName: string, userId: number): string {
  return `${packageName}@${userId}`
}

export function parsePackageUserTarget(value: string): PackageUserTarget | null {
  const target = parseScoopTarget(value)
  if (target?.kind !== 'package-user') return null
  return { packageName: target.packageName, userId: target.userId, targetKey: target.target }
}

export interface AppEntry extends PackageUserTarget {
  currentUser: boolean
  appName: string
  isSystem: boolean
}

export interface SelectableAppEntry extends AppEntry {
  selected: boolean
  selectedForAllUsers: boolean
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
  readonly #packageInfoCache = new Map<string, PackagesInfo>()
  readonly #subscribers = new Set<AppListSubscriber>()
  #entries: AppEntry[] = []
  #revision = 0
  #fetchPromise: Promise<boolean> | null = null
  #recommendedPackages: Promise<ReadonlySet<string>> | null = null

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
      .filter(entry => !entry.isSystem)
      .map(entry => ({
        ...entry,
        selected: selected.has(entry.packageName) || selected.has(entry.targetKey),
        selectedForAllUsers: selected.has(entry.packageName),
      }))
      .filter(entry => this.#matches(entry, normalizedQuery, filter))
      .sort((left, right) => this.#compareEntries(left, right))
  }

  getSystemEntries(query = ''): SelectableAppEntry[] {
    const selected = new Set(this.#config.get('target'))
    const normalizedQuery = normalizeSearchQuery(query)
    return this.#entries
      .filter(entry => entry.isSystem)
      .map(entry => ({
        ...entry,
        selected: selected.has(entry.packageName) || selected.has(entry.targetKey),
        selectedForAllUsers: selected.has(entry.packageName),
      }))
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

  setTargetSelected(target: PackageUserTarget, selected: boolean): void {
    if (parsePackageUserTarget(target.targetKey) === null) return
    const targets = new Set(this.#config.get('target'))
    if (selected) {
      if (targets.has(target.packageName) || targets.has(target.targetKey)) return
      targets.add(target.targetKey)
    } else {
      const removed = targets.delete(target.targetKey)
      if (targets.delete(target.packageName)) {
        // Editing one user of an existing all-user rule makes that package
        // explicit for the other discovered users. Unmapped per-user and UID
        // rules remain in the config instead of being discarded by this view.
        for (const entry of this.#entries) {
          if (entry.packageName === target.packageName && entry.userId !== target.userId) {
            targets.add(entry.targetKey)
          }
        }
      } else if (!removed) return
    }
    this.#config.set('target', [...targets])
    this.#emitChange()
  }

  toggleSelected(packageName: string): void {
    this.setSelected(packageName, !this.isSelected(packageName))
  }

  async selectRecommended(): Promise<void> {
    // Discover only on explicit selection, once per package-list refresh. Never
    // scan every installed package or issue one Binder request per app.
    this.#recommendedPackages ??= this.#queryRecommendedPackages().catch(error => {
      this.#recommendedPackages = null
      throw error
    })
    const recommended = await this.#recommendedPackages
    const targets = new Set(this.#config.get('target'))
    let changed = false
    for (const entry of this.#entries) {
      if (!recommended.has(entry.packageName)) continue
      if (targets.has(entry.packageName) || targets.has(entry.targetKey)) continue
      targets.add(entry.targetKey)
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
    const installedSystemTargets = new Set(
      this.#entries.filter(entry => entry.isSystem).map(entry => entry.targetKey),
    )
    const installedSystemApps = new Set(
      this.#entries.filter(entry => entry.isSystem).map(entry => entry.packageName),
    )
    const checked = new Set(
      checkedApps.filter(target => (
        installedSystemTargets.has(target) || installedSystemApps.has(target)
      )),
    )

    const targets = new Set(this.#config.get('target'))
    for (const target of [...installedSystemApps, ...installedSystemTargets]) {
      if (checked.has(target)) targets.add(target)
      else targets.delete(target)
    }
    this.#config.set('target', [...targets])
    this.#emitChange()
  }

  async save(): Promise<void> {
    await this.#config.write()
  }

  async #fetch(): Promise<boolean> {
    this.#recommendedPackages = null
    if (isDev()) return this.#replaceEntries(this.#getDevEntries())

    // KernelSU package APIs cross a synchronous WebView bridge. Yield before
    // each call so the navigation and progress animations can reach the screen.
    await afterPaint()
    const users = await queryAndroidUsers()
    const discovered: { user: AndroidUser, packages: string[], systemPackages: Set<string> }[] = []
    for (const user of users) {
      try {
        await afterPaint()
        const packages = await queryInstalledPackages(user.userId)
        await afterPaint()
        const systemPackages = new Set(await queryInstalledPackages(user.userId, 'system'))
        discovered.push({ user, packages, systemPackages })
      } catch (error) {
        if (user.current) throw error
        // Locked, partial or removed profiles can be inaccessible. Keep the
        // successfully queried users instead of discarding their app list.
      }
    }
    const packages = [...new Set(discovered.flatMap(user => user.packages))]
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

    return this.#replaceEntries(discovered.flatMap(({ user, packages, systemPackages }) => (
      packages.map(packageName => {
        const info = this.#packageInfoCache.get(packageName)
        return {
          packageName,
          userId: user.userId,
          currentUser: user.current,
          targetKey: formatPackageUserTarget(packageName, user.userId),
          appName: typeof info?.appLabel === 'string' && info.appLabel
            ? info.appLabel
            : packageName,
          // The bridge cannot address a particular Android user. Labels can
          // be reused, but installed state and classification come from the
          // explicit per-user PackageManager query only.
          isSystem: systemPackages.has(packageName),
        }
      })
    )))
  }

  async #queryRecommendedPackages(): Promise<ReadonlySet<string>> {
    const excluded = new Set(ROOT_TOOL_PACKAGES)
    let userPackages: string[]
    if (isDev()) {
      userPackages = this.#entries.filter(entry => !entry.isSystem).map(entry => entry.packageName)
    } else {
      await afterPaint()
      userPackages = this.#entries.filter(entry => !entry.isSystem).map(entry => entry.packageName)
      // PackageManager limits this dump to users of these declared permissions;
      // it does not request the full installed-app dump or inspect private data.
      const commands = [
        'dumpsys -t 8 package permission moe.shizuku.manager.permission.API_V23 moe.shizuku.manager.permission.API android.permission.ACCESS_SUPERUSER com.topjohnwu.magisk.permission.REQUEST_SU',
        ...[...new Set(this.#entries.map(entry => entry.userId))].map(userId => (
          `cmd package query-activities --brief --components --user ${userId} -a android.intent.action.MAIN -c de.robv.android.xposed.category.MODULE_SETTINGS`
        )),
      ]
      for (const command of commands) {
        await afterPaint()
        const result = await exec(command)
        if (result.errno !== 0 || /permission denial|unknown command|can't find service|error:|securityexception|dump timed out/i.test(`${result.stdout}\n${result.stderr}`)) {
          // Leave the current selection intact when classification is unavailable.
          throw new Error('Unable to identify app permissions for recommended selection')
        }
        for (const line of result.stdout.split(/\r?\n/)) {
          const packageName = line.match(/^\s*Package \[([^\]]+)\]/)?.[1]
            ?? line.trim().match(/^([A-Za-z][A-Za-z0-9_.]*)\//)?.[1]
          if (packageName && isValidPackageName(packageName)) excluded.add(packageName)
        }
      }
    }
    return new Set([
      ...userPackages.filter(packageName => !excluded.has(packageName)),
      ...RECOMMENDED_SYSTEM_APPS,
    ])
  }

  #replaceEntries(entries: AppEntry[]): boolean {
    const previousEntries = new Map(this.#entries.map(entry => [entry.targetKey, entry]))
    const changed = entries.length !== this.#entries.length || entries.some(entry => {
      const previous = previousEntries.get(entry.targetKey)
      return previous?.appName !== entry.appName || previous.isSystem !== entry.isSystem
        || previous.currentUser !== entry.currentUser
    })
    if (!changed) return false

    this.#entries = entries
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
    return `${entry.appName}\n${entry.packageName}\n${entry.targetKey}`
      .toLocaleLowerCase()
      .includes(normalizedQuery)
  }

  #compareEntries(left: SelectableAppEntry, right: SelectableAppEntry): number {
    if (left.currentUser !== right.currentUser) return left.currentUser ? -1 : 1
    if (left.userId !== right.userId) return left.userId - right.userId
    if (left.selected !== right.selected) return left.selected ? -1 : 1
    return left.appName.localeCompare(right.appName) || left.packageName.localeCompare(right.packageName)
  }

  #emitChange(): void {
    this.#revision++
    const snapshot = this.getSnapshot()
    for (const subscriber of this.#subscribers) subscriber(snapshot)
  }

  #getDevEntries(): AppEntry[] {
    return [
      { packageName: 'io.github.vvb2060.keyattestation', userId: 0, currentUser: true, targetKey: 'io.github.vvb2060.keyattestation@0', appName: 'Key Attestation', isSystem: false },
      { packageName: 'com.example.app', userId: 0, currentUser: true, targetKey: 'com.example.app@0', appName: 'Example App', isSystem: false },
      { packageName: 'com.example.banking', userId: 0, currentUser: true, targetKey: 'com.example.banking@0', appName: 'Banking App', isSystem: false },
      { packageName: 'com.google.android.gms', userId: 0, currentUser: true, targetKey: 'com.google.android.gms@0', appName: 'Google Play services', isSystem: true },
      { packageName: 'com.android.vending', userId: 0, currentUser: true, targetKey: 'com.android.vending@0', appName: 'Google Play Store', isSystem: true },
      { packageName: 'com.google.android.gsf', userId: 0, currentUser: true, targetKey: 'com.google.android.gsf@0', appName: 'Google Services Framework', isSystem: true },
      { packageName: 'com.example.app', userId: 10, currentUser: false, targetKey: 'com.example.app@10', appName: 'Example App', isSystem: false },
    ]
  }
}

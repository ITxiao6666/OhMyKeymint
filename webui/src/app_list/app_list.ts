import { getPackagesInfo, listPackages } from 'kernelsu-alt'
import type { PackagesInfo } from 'kernelsu-alt'
import type { Config } from '../config'
import { i18n } from '../i18n'
import { isValidPackageName } from '../package_name'
import { isDev } from '../utils/dev'
import './app_list.scss'

const DEFAULT_VISIBLE_SYSTEM_APPS = [
  'com.google.android.gsf',
  'com.google.android.gms',
  'com.android.vending',
]

const PACKAGE_INFO_BATCH_SIZE = 32
const SYSTEM_APP_RENDER_BATCH_SIZE = 16

function nextFrame(): Promise<void> {
  return new Promise(resolve => window.requestAnimationFrame(() => resolve()))
}

function afterPaint(): Promise<void> {
  return new Promise(resolve => {
    window.requestAnimationFrame(() => window.setTimeout(resolve, 0))
  })
}

function i18nText(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

export type SelectionFilter = 'all' | 'selected' | 'unselected'

export interface AppEntry {
  packageName: string
  appName: string
  isSystem: boolean
}

export class AppList {
  readonly #config: Config
  #entries: AppEntry[] = []
  #visibleSystemApps = new Set(DEFAULT_VISIBLE_SYSTEM_APPS)
  #packageInfoCache = new Map<string, PackagesInfo>()
  #iconObserver: IntersectionObserver | null = null
  #systemAppIconObserver: IntersectionObserver | null = null
  #entriesVersion = 0
  #systemAppRenderedVersion = -1
  #systemAppRenderGeneration = 0
  #systemAppContainer: HTMLElement | null = null
  #container: HTMLElement | null = null
  #searchQuery = ''
  #selectionFilter: SelectionFilter = 'all'
  #selectionCallbacks: Array<(count: number) => void> = []
  menuOpen = false

  constructor(config: Config) {
    this.#config = config
  }

  async fetch(): Promise<boolean> {
    if (isDev()) {
      const hadEntries = this.#entries.length !== 0
      this.#initDevMode()
      if (!hadEntries) this.#entriesVersion++
      return !hadEntries
    }

    // KernelSU's package APIs cross a synchronous WebView bridge internally.
    // Yield first so navigation and progress animations can paint before it runs.
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
        // Package names remain usable when labels or system metadata are unavailable.
      }
    }

    const entries = packages.map(packageName => {
      const info = this.#packageInfoCache.get(packageName)
      return {
        packageName,
        appName: typeof info?.appLabel === 'string' && info.appLabel ? info.appLabel : packageName,
        isSystem: info?.isSystem ?? false,
      }
    })

    const previousEntries = new Map(this.#entries.map(entry => [entry.packageName, entry]))
    const changed = entries.length !== this.#entries.length || entries.some(entry => {
      const previous = previousEntries.get(entry.packageName)
      return previous?.appName !== entry.appName || previous.isSystem !== entry.isSystem
    })
    this.#entries = entries
    if (changed) this.#entriesVersion++
    return changed
  }

  getEntries(): AppEntry[] {
    return this.#entries
  }

  getSelectedCount(): number {
    return new Set(this.#config.get('target')).size
  }

  onSelectionChange(callback: (count: number) => void): void {
    this.#selectionCallbacks.push(callback)
  }

  setSearchQuery(query: string): void {
    this.#searchQuery = query.trim().toLocaleLowerCase()
    this.#applyFilters()
  }

  setSelectionFilter(filter: SelectionFilter): void {
    this.#selectionFilter = filter
    this.#applyFilters()
  }

  async save(): Promise<void> {
    await this.#config.write()
  }

  async refresh(force = true): Promise<void> {
    if (force) {
      await this.#config.read()
      await this.fetch()
      this.syncSystemAppsWithConfig()
    }
    if (this.#container) {
      this.renderAppList(this.#container)
    }
  }

  syncSystemAppsWithConfig(): void {
    const target = new Set(this.#config.get('target'))
    for (const entry of this.#entries) {
      if (entry.isSystem && target.has(entry.packageName)) {
        this.#visibleSystemApps.add(entry.packageName)
      }
    }
  }

  selectAll(): void {
    if (!this.#container) return
    const target = new Set(this.#config.get('target'))
    this.#container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      const packageName = card.dataset.package
      if (packageName) target.add(packageName)
    })
    this.#config.set('target', [...target])
    this.#syncCheckboxes()
    this.#applyFilters()
    this.#emitSelectionChange()
  }

  deselectAll(): void {
    this.#config.set('target', [])
    this.#syncCheckboxes()
    this.#applyFilters()
    this.#emitSelectionChange()
  }

  renderAppList(container: HTMLElement): void {
    this.#container = container
    container.replaceChildren()

    const target = new Set(this.#config.get('target'))
    const displayed = this.#entries.filter(
      entry => !entry.isSystem || this.#visibleSystemApps.has(entry.packageName),
    )
    displayed.sort((left, right) => {
      const leftTargeted = target.has(left.packageName)
      const rightTargeted = target.has(right.packageName)
      if (leftTargeted !== rightTargeted) return leftTargeted ? -1 : 1
      return left.appName.localeCompare(right.appName)
    })

    const fragment = document.createDocumentFragment()
    for (const entry of displayed) {
      fragment.appendChild(this.#createCard(entry, target.has(entry.packageName), 'target'))
    }
    const empty = document.createElement('div')
    empty.className = 'app-list-empty'
    empty.textContent = i18nText('app_targets_empty', 'No matching apps')
    empty.hidden = true
    fragment.appendChild(empty)
    container.appendChild(fragment)
    this.#setupCardListeners(container)
    this.#applyFilters()

    this.#iconObserver?.disconnect()
    this.#iconObserver = this.#setupIconObserver(container)
  }

  isSystemAppListReady(container: HTMLElement): boolean {
    return this.#systemAppContainer === container
      && this.#systemAppRenderedVersion === this.#entriesVersion
  }

  cancelSystemAppRender(): void {
    this.#systemAppRenderGeneration++
    this.#systemAppIconObserver?.disconnect()
  }

  async renderSystemAppList(container: HTMLElement): Promise<boolean> {
    const generation = ++this.#systemAppRenderGeneration
    this.#systemAppIconObserver?.disconnect()

    if (this.isSystemAppListReady(container)) {
      this.#syncSystemAppCheckboxes(container)
      this.#setupSystemAppListeners(container)
      this.#systemAppIconObserver = this.#setupIconObserver(container)
      return true
    }

    container.replaceChildren()
    const target = new Set(this.#config.get('target'))
    const systemEntries = this.#entries.filter(entry => entry.isSystem)
    systemEntries.sort((left, right) => {
      const leftVisible = this.#visibleSystemApps.has(left.packageName)
      const rightVisible = this.#visibleSystemApps.has(right.packageName)
      if (leftVisible !== rightVisible) return leftVisible ? -1 : 1
      return left.appName.localeCompare(right.appName)
    })

    for (let offset = 0; offset < systemEntries.length; offset += SYSTEM_APP_RENDER_BATCH_SIZE) {
      if (generation !== this.#systemAppRenderGeneration) return false
      const fragment = document.createDocumentFragment()
      const batch = systemEntries.slice(offset, offset + SYSTEM_APP_RENDER_BATCH_SIZE)
      for (const entry of batch) {
        fragment.appendChild(this.#createCard(entry, target.has(entry.packageName), 'system'))
      }
      container.appendChild(fragment)
      if (offset + SYSTEM_APP_RENDER_BATCH_SIZE < systemEntries.length) await nextFrame()
    }
    if (generation !== this.#systemAppRenderGeneration) return false

    this.#setupSystemAppListeners(container)
    this.#systemAppIconObserver = this.#setupIconObserver(container)
    this.#systemAppContainer = container
    this.#systemAppRenderedVersion = this.#entriesVersion
    return true
  }

  async saveSystemAppSelection(checkedApps: string[]): Promise<void> {
    const checked = new Set(checkedApps.filter(isValidPackageName))
    this.#visibleSystemApps = new Set([...DEFAULT_VISIBLE_SYSTEM_APPS, ...checked])
    this.#systemAppRenderedVersion = -1

    const target = new Set(this.#config.get('target'))
    for (const entry of this.#entries) {
      if (!entry.isSystem) continue
      if (checked.has(entry.packageName)) {
        target.add(entry.packageName)
      } else {
        target.delete(entry.packageName)
      }
    }
    this.#config.set('target', [...target])
    await this.refresh(false)
    this.#emitSelectionChange()
  }

  #createCard(entry: AppEntry, checked: boolean, mode: 'target' | 'system'): HTMLElement {
    const cardBox = document.createElement('div')
    cardBox.className = 'card-box'

    const card = document.createElement('div')
    card.className = `card miuix-card card-alpha content${checked ? ' selected' : ''}`
    card.dataset.package = entry.packageName
    card.dataset.selected = String(checked)
    card.dataset.search = `${entry.appName}\n${entry.packageName}`.toLocaleLowerCase()

    if (mode === 'target') card.appendChild(document.createElement('md-ripple'))

    const label = document.createElement('label')
    label.className = 'name'

    const iconContainer = document.createElement('div')
    iconContainer.className = 'app-icon-container'
    const loader = document.createElement('div')
    loader.className = 'loader'
    const image = document.createElement('img')
    image.className = 'app-icon'
    image.alt = entry.appName
    image.draggable = false
    const fallback = document.createElement('div')
    fallback.className = 'app-icon-fallback'
    iconContainer.append(loader, image, fallback)

    const info = document.createElement('div')
    info.className = 'app-info'
    const appName = document.createElement('div')
    appName.className = 'app-name'
    appName.textContent = entry.appName
    const packageName = document.createElement('div')
    packageName.className = 'package-name'
    packageName.textContent = entry.packageName
    info.append(appName, packageName)
    label.append(iconContainer, info)

    card.tabIndex = 0
    card.setAttribute('role', 'checkbox')
    card.setAttribute('aria-checked', String(checked))

    if (mode === 'system') {
      cardBox.classList.add('system-app-item')
      card.classList.add('system-app-card', 'miuix-preference-row')
      const checkbox = document.createElement('span')
      checkbox.className = 'system-app-checkbox'
      checkbox.setAttribute('aria-hidden', 'true')
      checkbox.innerHTML = /* html */ `
        <svg viewBox="0 0 26 26" focusable="false">
          <path d="M8.576 13.660 L11.643 16.843 L17.500 9.291" pathLength="1"></path>
        </svg>
      `
      card.append(label, checkbox)
    } else {
      const selection = document.createElement('span')
      selection.className = 'selection-indicator'
      const selectionIcon = document.createElement('md-icon')
      selectionIcon.textContent = 'check'
      selectionIcon.setAttribute('aria-hidden', 'true')
      selection.appendChild(selectionIcon)
      card.append(label, selection)
    }
    cardBox.appendChild(card)
    return cardBox
  }

  #setupCardListeners(container: HTMLElement): void {
    container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      card.onclick = event => {
        event.preventDefault()
        if (this.menuOpen) return
        const packageName = card.dataset.package
        if (!packageName) return

        const target = new Set(this.#config.get('target'))
        if (target.has(packageName)) target.delete(packageName)
        else target.add(packageName)
        this.#config.set('target', [...target])
        this.#syncCard(card, target.has(packageName))
        this.#applyFilters()
        this.#emitSelectionChange()
      }
      card.onkeydown = event => {
        if (event.key !== 'Enter' && event.key !== ' ') return
        event.preventDefault()
        card.click()
      }
    })
  }

  #setupSystemAppListeners(container: HTMLElement): void {
    container.onclick = event => {
      const eventPath = event.composedPath()
      const card = eventPath.find((element): element is HTMLElement => (
        element instanceof HTMLElement && element.classList.contains('card')
      ))
      if (!card || !container.contains(card)) return
      event.preventDefault()
      this.#syncCard(card, card.dataset.selected !== 'true')
    }
    container.onkeydown = event => {
      if (event.key !== 'Enter' && event.key !== ' ') return
      const card = event.target instanceof HTMLElement
        ? event.target.closest<HTMLElement>('.card')
        : null
      if (!card || !container.contains(card)) return
      event.preventDefault()
      card.click()
    }
  }

  #syncSystemAppCheckboxes(container: HTMLElement): void {
    const target = new Set(this.#config.get('target'))
    container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      const packageName = card.dataset.package
      this.#syncCard(card, packageName !== undefined && target.has(packageName))
    })
  }

  #syncCheckboxes(): void {
    if (!this.#container) return
    const target = new Set(this.#config.get('target'))
    this.#container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      const packageName = card.dataset.package
      this.#syncCard(card, packageName !== undefined && target.has(packageName))
    })
  }

  #syncCard(card: HTMLElement, checked: boolean): void {
    card.classList.toggle('selected', checked)
    card.dataset.selected = String(checked)
    if (card.getAttribute('role') === 'checkbox') {
      card.setAttribute('aria-checked', String(checked))
    }
  }

  #applyFilters(): void {
    if (!this.#container) return
    let visible = 0
    this.#container.querySelectorAll<HTMLElement>('.card-box').forEach(box => {
      const card = box.querySelector<HTMLElement>('.card')
      const selected = card?.dataset.selected === 'true'
      const selectionMatches = this.#selectionFilter === 'all'
        || (this.#selectionFilter === 'selected' && selected)
        || (this.#selectionFilter === 'unselected' && !selected)
      const searchMatches = !this.#searchQuery
        || (card?.dataset.search ?? '').includes(this.#searchQuery)
      const matches = selectionMatches && searchMatches
      box.hidden = !matches
      if (matches) visible++
    })
    const empty = this.#container.querySelector<HTMLElement>('.app-list-empty')
    if (empty) empty.hidden = visible !== 0
  }

  #emitSelectionChange(): void {
    const count = this.getSelectedCount()
    this.#selectionCallbacks.forEach(callback => callback(count))
  }

  #setupIconObserver(container: HTMLElement): IntersectionObserver {
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue
        const iconContainer = entry.target as HTMLElement
        const card = iconContainer.closest<HTMLElement>('.card')
        const packageName = card?.dataset.package
        if (packageName) this.#loadIcon(iconContainer, packageName)
        observer.unobserve(iconContainer)
      }
    }, { rootMargin: '100px', threshold: 0.1 })

    container.querySelectorAll('.app-icon-container').forEach(element => observer.observe(element))
    return observer
  }

  #loadIcon(container: HTMLElement, packageName: string): void {
    if (container.dataset.iconState) return
    const image = container.querySelector<HTMLImageElement>('.app-icon')
    const loader = container.querySelector<HTMLElement>('.loader')
    const fallback = container.querySelector<HTMLElement>('.app-icon-fallback')
    if (!image) return

    container.dataset.iconState = 'loading'
    container.classList.add('icon-loading')
    image.onload = () => {
      container.dataset.iconState = 'loaded'
      container.classList.remove('icon-loading')
      if (loader) loader.style.display = 'none'
      image.style.opacity = '1'
    }
    image.onerror = () => {
      container.dataset.iconState = 'error'
      container.classList.remove('icon-loading')
      image.style.display = 'none'
      if (fallback && !fallback.hasChildNodes()) {
        const fallbackIcon = document.createElement('md-icon')
        fallbackIcon.textContent = 'android'
        fallback.appendChild(fallbackIcon)
      }
      fallback?.classList.add('visible')
      if (loader) loader.style.display = 'none'
    }
    image.src = `ksu://icon/${packageName}`
  }

  #initDevMode(): void {
    this.#entries = [
      { packageName: 'io.github.vvb2060.keyattestation', appName: 'Key Attestation', isSystem: false },
      { packageName: 'com.example.app', appName: 'Example App', isSystem: false },
      { packageName: 'com.example.banking', appName: 'Banking App', isSystem: false },
      { packageName: 'com.google.android.gms', appName: 'Google Play services', isSystem: true },
      { packageName: 'com.android.vending', appName: 'Google Play Store', isSystem: true },
      { packageName: 'com.google.android.gsf', appName: 'Google Services Framework', isSystem: true },
    ]
  }
}

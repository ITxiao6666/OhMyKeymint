import { getPackagesInfo, listPackages } from 'kernelsu-alt'
import type { PackagesInfo } from 'kernelsu-alt'
import type { Config } from '../config'
import { isValidPackageName } from '../package_name'
import { isDev } from '../utils/dev'
import './app_list.scss'

const DEFAULT_VISIBLE_SYSTEM_APPS = [
  'com.google.android.gsf',
  'com.google.android.gms',
  'com.android.vending',
]

type CheckboxElement = HTMLElement & { checked: boolean }

export interface AppEntry {
  packageName: string
  appName: string
  isSystem: boolean
}

export class AppList {
  readonly #config: Config
  #entries: AppEntry[] = []
  #visibleSystemApps = new Set(DEFAULT_VISIBLE_SYSTEM_APPS)
  #iconObserver: IntersectionObserver | null = null
  #systemAppIconObserver: IntersectionObserver | null = null
  #container: HTMLElement | null = null
  menuOpen = false

  constructor(config: Config) {
    this.#config = config
  }

  async fetch(): Promise<void> {
    if (isDev()) {
      this.#initDevMode()
      return
    }

    const rawPackages = await listPackages('all').catch(() => [])
    const packages = [...new Set(rawPackages.filter(isValidPackageName))]
    let infos: PackagesInfo[] = []
    try {
      infos = await getPackagesInfo(packages) as PackagesInfo[]
    } catch {
      // Package names remain usable when labels or system metadata are unavailable.
    }

    const infoByPackage = new Map(
      infos
        .filter(info => isValidPackageName(info.packageName))
        .map(info => [info.packageName, info]),
    )

    this.#entries = packages.map(packageName => {
      const info = infoByPackage.get(packageName)
      return {
        packageName,
        appName: typeof info?.appLabel === 'string' && info.appLabel ? info.appLabel : packageName,
        isSystem: info?.isSystem ?? false,
      }
    })
  }

  getEntries(): AppEntry[] {
    return this.#entries
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
      if (force) window.scrollTo(0, 0)
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
  }

  deselectAll(): void {
    this.#config.set('target', [])
    this.#syncCheckboxes()
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
      fragment.appendChild(this.#createCard(entry, target.has(entry.packageName)))
    }
    container.appendChild(fragment)
    this.#setupCardListeners(container)

    this.#iconObserver?.disconnect()
    this.#iconObserver = this.#setupIconObserver(container)
  }

  renderSystemAppList(container: HTMLElement): void {
    container.replaceChildren()
    const systemEntries = this.#entries.filter(entry => entry.isSystem)
    systemEntries.sort((left, right) => {
      const leftVisible = this.#visibleSystemApps.has(left.packageName)
      const rightVisible = this.#visibleSystemApps.has(right.packageName)
      if (leftVisible !== rightVisible) return leftVisible ? -1 : 1
      return left.appName.localeCompare(right.appName)
    })

    const fragment = document.createDocumentFragment()
    for (const entry of systemEntries) {
      fragment.appendChild(this.#createCard(entry, this.#visibleSystemApps.has(entry.packageName)))
    }
    container.appendChild(fragment)
    this.#setupSystemAppListeners(container)

    this.#systemAppIconObserver?.disconnect()
    this.#systemAppIconObserver = this.#setupIconObserver(container)
  }

  async saveSystemAppSelection(checkedApps: string[]): Promise<void> {
    const checked = new Set(checkedApps.filter(isValidPackageName))
    this.#visibleSystemApps = new Set([...DEFAULT_VISIBLE_SYSTEM_APPS, ...checked])

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
  }

  #createCard(entry: AppEntry, checked: boolean): HTMLElement {
    const cardBox = document.createElement('div')
    cardBox.className = 'card-box'

    const card = document.createElement('div')
    card.className = `card card-alpha content${checked ? ' selected' : ''}`
    card.dataset.package = entry.packageName

    card.appendChild(document.createElement('md-ripple'))

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
    const fallbackIcon = document.createElement('md-icon')
    fallbackIcon.textContent = 'android'
    fallback.appendChild(fallbackIcon)
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

    const checkbox = document.createElement('md-checkbox') as CheckboxElement
    checkbox.className = 'checkbox'
    checkbox.checked = checked
    checkbox.setAttribute('touch-target', 'wrapper')
    card.append(label, checkbox)
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
      }
    })
  }

  #setupSystemAppListeners(container: HTMLElement): void {
    container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      card.onclick = event => {
        event.preventDefault()
        const checkbox = card.querySelector<CheckboxElement>('md-checkbox')
        if (!checkbox) return
        this.#syncCard(card, !checkbox.checked)
      }
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
    const checkbox = card.querySelector<CheckboxElement>('md-checkbox')
    if (checkbox) checkbox.checked = checked
    card.classList.toggle('selected', checked)
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
    const image = container.querySelector<HTMLImageElement>('.app-icon')
    const loader = container.querySelector<HTMLElement>('.loader')
    const fallback = container.querySelector<HTMLElement>('.app-icon-fallback')
    if (!image) return

    image.onload = () => {
      if (loader) loader.style.display = 'none'
      image.style.opacity = '1'
    }
    image.onerror = () => {
      image.style.display = 'none'
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

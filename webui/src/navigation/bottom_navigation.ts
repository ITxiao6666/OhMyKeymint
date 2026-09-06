import { i18n } from '../i18n'
import './bottom_navigation.scss'

export type PageId = 'home' | 'tools' | 'settings'

interface NavigationItem {
  id: PageId
  icon: string
  labelKey: string
  fallback: string
}

const ITEMS: readonly NavigationItem[] = [
  { id: 'home', icon: 'home', labelKey: 'nav_home', fallback: 'Home' },
  { id: 'tools', icon: 'build', labelKey: 'nav_tools', fallback: 'Tools' },
  { id: 'settings', icon: 'settings', labelKey: 'nav_settings', fallback: 'Settings' },
]

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

export class BottomNavigation {
  #activePage: PageId = 'home'
  #element: HTMLElement | null = null
  #callbacks: Array<(page: PageId) => void> = []

  getElement(): HTMLElement {
    const navigation = document.createElement('nav')
    navigation.className = 'bottom-navigation'
    navigation.setAttribute('aria-label', translate('nav_main_aria', 'Main navigation'))

    for (const item of ITEMS) {
      const button = document.createElement('button')
      button.type = 'button'
      button.className = 'bottom-navigation-item'
      button.dataset.page = item.id
      button.setAttribute('aria-label', translate(item.labelKey, item.fallback))

      const icon = document.createElement('md-icon')
      icon.className = 'bottom-navigation-icon'
      icon.textContent = item.icon
      icon.setAttribute('aria-hidden', 'true')

      const label = document.createElement('span')
      label.className = 'bottom-navigation-label'
      label.textContent = translate(item.labelKey, item.fallback)

      button.append(icon, label)
      button.onclick = () => this.select(item.id)
      navigation.appendChild(button)
    }

    this.#element = navigation
    this.#syncSelection()
    return navigation
  }

  select(page: PageId, emit = true): void {
    if (this.#activePage === page) return
    this.#activePage = page
    this.#syncSelection()
    if (emit) this.#callbacks.forEach(callback => callback(page))
  }

  onChange(callback: (page: PageId) => void): void {
    this.#callbacks.push(callback)
  }

  get activePage(): PageId {
    return this.#activePage
  }

  #syncSelection(): void {
    this.#element?.querySelectorAll<HTMLElement>('.bottom-navigation-item').forEach(item => {
      const active = item.dataset.page === this.#activePage
      item.classList.toggle('active', active)
      if (active) item.setAttribute('aria-current', 'page')
      else item.removeAttribute('aria-current')
    })
  }
}

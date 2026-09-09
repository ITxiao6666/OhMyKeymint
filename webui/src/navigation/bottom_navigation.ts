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

const FLOATING_BAR_PADDING = 4
const FLOATING_TAB_WIDTH = 76

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

export class BottomNavigation {
  #activePage: PageId = 'home'
  #element: HTMLElement | null = null
  #callbacks: Array<(page: PageId) => void> = []
  #activePointer: number | null = null
  #pointerStartX = 0
  #pointerStartVisualIndex = 0
  #pointerBoundsLeft = 0
  #pointerBoundsRight = 0
  #pointerTabWidth = FLOATING_TAB_WIDTH
  #ignoreNextClick = false
  #globalPointerFallbacksAttached = false

  getElement(): HTMLElement {
    const navigation = document.createElement('nav')
    navigation.className = 'bottom-navigation miuix-navigation-bar'
    navigation.setAttribute('aria-label', translate('nav_main_aria', 'Main navigation'))
    navigation.setAttribute('role', 'tablist')

    const surface = document.createElement('div')
    surface.className = 'bottom-navigation-surface'
    surface.setAttribute('aria-hidden', 'true')
    navigation.appendChild(surface)

    for (const item of ITEMS) {
      const button = document.createElement('button')
      button.type = 'button'
      button.className = 'bottom-navigation-item miuix-navigation-item'
      button.dataset.page = item.id
      button.setAttribute('aria-label', translate(item.labelKey, item.fallback))
      button.setAttribute('role', 'tab')

      const icon = document.createElement('md-icon')
      icon.className = 'bottom-navigation-icon miuix-navigation-icon'
      icon.textContent = item.icon
      icon.setAttribute('aria-hidden', 'true')

      const label = document.createElement('span')
      label.className = 'bottom-navigation-label miuix-navigation-label'
      label.textContent = translate(item.labelKey, item.fallback)

      button.append(icon, label)
      button.onclick = event => {
        if (this.#ignoreNextClick) {
          this.#ignoreNextClick = false
          event.preventDefault()
          return
        }
        this.select(item.id)
      }
      navigation.appendChild(button)
    }

    const indicator = document.createElement('div')
    indicator.className = 'bottom-navigation-indicator'
    indicator.setAttribute('aria-hidden', 'true')
    const accentTrack = document.createElement('div')
    accentTrack.className = 'bottom-navigation-accent-track'
    accentTrack.setAttribute('aria-hidden', 'true')
    for (const item of ITEMS) {
      const accentItem = document.createElement('div')
      accentItem.className = 'bottom-navigation-accent-item'
      accentItem.dataset.page = item.id
      const icon = document.createElement('md-icon')
      icon.className = 'bottom-navigation-accent-icon'
      icon.textContent = item.icon
      const label = document.createElement('span')
      label.className = 'bottom-navigation-accent-label'
      label.textContent = translate(item.labelKey, item.fallback)
      accentItem.append(icon, label)
      accentTrack.appendChild(accentItem)
    }
    navigation.append(indicator, accentTrack)

    navigation.onpointerdown = event => this.#onPointerDown(event)
    navigation.onpointermove = event => this.#onPointerMove(event)
    navigation.onpointerup = event => this.#onPointerUp(event)
    navigation.onpointercancel = event => this.#onPointerCancel(event)
    navigation.onlostpointercapture = event => this.#onPointerCancel(event)

    this.#element = navigation
    this.#attachGlobalPointerFallbacks()
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
    if (this.#element) this.#element.dataset.activePage = this.#activePage
    this.#element?.querySelectorAll<HTMLElement>('.bottom-navigation-item').forEach(item => {
      const active = item.dataset.page === this.#activePage
      item.classList.toggle('active', active)
      item.setAttribute('aria-selected', String(active))
      if (active) item.setAttribute('aria-current', 'page')
      else item.removeAttribute('aria-current')
    })
    this.#setIndicatorPosition(this.#visualIndex(ITEMS.findIndex(item => item.id === this.#activePage)))
  }

  #onPointerDown(event: PointerEvent): void {
    if (
      !this.#isLiquidGlass()
      || !event.isPrimary
      || event.button !== 0
      || !this.#element
      || this.#activePointer !== null
    ) return
    const bounds = this.#element.getBoundingClientRect()
    const tabWidth = FLOATING_TAB_WIDTH

    this.#activePointer = event.pointerId
    this.#pointerStartX = event.clientX
    this.#pointerBoundsLeft = bounds.left
    this.#pointerBoundsRight = bounds.right
    this.#pointerTabWidth = tabWidth
    this.#pointerStartVisualIndex = Math.min(
      ITEMS.length - 1,
      Math.max(
        0,
        Math.floor((event.clientX - bounds.left - FLOATING_BAR_PADDING) / tabWidth),
      ),
    )
    this.#setIndicatorPosition(this.#pointerStartVisualIndex)
    this.#setPressedVisualIndex(this.#pointerStartVisualIndex)
    this.#element.style.setProperty(
      '--omk-liquid-highlight-x',
      `${event.clientX - bounds.left}px`,
    )
    this.#element.classList.add('is-pressing')
    try {
      this.#element.setPointerCapture(event.pointerId)
    } catch {
      // Old Android WebViews can reject capture while the pointer is transitioning.
    }
    event.preventDefault()
  }

  #onPointerMove(event: PointerEvent): void {
    if (this.#activePointer !== event.pointerId || !this.#element) return
    if (Math.abs(event.clientX - this.#pointerStartX) > 1) {
      this.#element.classList.add('is-dragging')
    }
    if (this.#isPointerWithinBounds(event.clientX)) this.#updatePointerPosition(event.clientX)
    event.preventDefault()
  }

  #onPointerUp(event: PointerEvent): void {
    if (this.#activePointer !== event.pointerId || !this.#element) return
    if (this.#isPointerWithinBounds(event.clientX)) this.#updatePointerPosition(event.clientX)
    const target = ITEMS.find(item => item.id === this.#element?.dataset.pressedPage)?.id
    this.#finishPointer(event.pointerId)
    if (target) this.select(target)
    this.#syncIndicatorPosition()
    this.#ignoreNextClick = true
    window.setTimeout(() => {
      this.#ignoreNextClick = false
    }, 0)
    event.preventDefault()
  }

  #onPointerCancel(event: PointerEvent): void {
    if (this.#activePointer !== event.pointerId) return
    this.#cancelActivePointer()
  }

  #finishPointer(pointerId: number): void {
    if (!this.#element) return
    this.#activePointer = null
    this.#element.classList.remove('is-pressing', 'is-dragging')
    delete this.#element.dataset.pressedPage
    this.#element.querySelectorAll(
      '.bottom-navigation-item.is-pressed, .bottom-navigation-accent-item.is-pressed',
    ).forEach(item => {
      item.classList.remove('is-pressed')
    })
    this.#element.style.setProperty('--omk-liquid-panel-offset', '0px')
    if (this.#element.hasPointerCapture(pointerId)) {
      try {
        this.#element.releasePointerCapture(pointerId)
      } catch {
        // Capture may already have been released by the WebView.
      }
    }
  }

  #updatePointerPosition(clientX: number): void {
    if (!this.#element) return
    const distance = clientX - this.#pointerStartX
    const position = Math.min(
      ITEMS.length - 1,
      Math.max(0, this.#pointerStartVisualIndex + distance / this.#pointerTabWidth),
    )
    this.#setIndicatorPosition(position)

    const visualIndex = Math.min(
      ITEMS.length - 1,
      Math.max(
        0,
        Math.floor(
          (clientX - this.#pointerBoundsLeft - FLOATING_BAR_PADDING) / this.#pointerTabWidth,
        ),
      ),
    )
    this.#setPressedVisualIndex(visualIndex)

    const totalWidth = this.#pointerBoundsRight - this.#pointerBoundsLeft
    const fraction = Math.min(1, Math.abs(distance) / Math.max(1, totalWidth))
    const offset = Math.sign(distance) * 4 * (1 - (1 - fraction) ** 2)
    this.#element.style.setProperty('--omk-liquid-panel-offset', `${offset}px`)
    this.#element.style.setProperty(
      '--omk-liquid-highlight-x',
      `${clientX - this.#pointerBoundsLeft}px`,
    )
  }

  #setPressedVisualIndex(visualIndex: number): void {
    if (!this.#element) return
    const logicalIndex = document.documentElement.dir === 'rtl'
      ? ITEMS.length - 1 - visualIndex
      : visualIndex
    const pressedPage = ITEMS[logicalIndex].id
    this.#element.dataset.pressedPage = pressedPage
    this.#element.querySelectorAll<HTMLElement>(
      '.bottom-navigation-item, .bottom-navigation-accent-item',
    ).forEach(item => {
      item.classList.toggle('is-pressed', item.dataset.page === pressedPage)
    })
  }

  #isPointerWithinBounds(clientX: number): boolean {
    return clientX >= this.#pointerBoundsLeft && clientX <= this.#pointerBoundsRight
  }

  #syncIndicatorPosition(): void {
    const index = ITEMS.findIndex(item => item.id === this.#activePage)
    this.#setIndicatorPosition(this.#visualIndex(index))
  }

  #setIndicatorPosition(position: number): void {
    if (!this.#element) return
    const offset = position * FLOATING_TAB_WIDTH
    this.#element.style.setProperty('--omk-liquid-indicator-offset', `${offset}px`)
  }

  #attachGlobalPointerFallbacks(): void {
    if (this.#globalPointerFallbacksAttached) return
    this.#globalPointerFallbacksAttached = true
    window.addEventListener('pointerup', event => this.#onPointerUp(event))
    window.addEventListener('pointercancel', event => this.#onPointerCancel(event))
    window.addEventListener('blur', () => this.#cancelActivePointer())
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'visible') this.#cancelActivePointer()
    })
  }

  #cancelActivePointer(): void {
    const pointerId = this.#activePointer
    if (pointerId === null) return
    this.#finishPointer(pointerId)
    this.#syncIndicatorPosition()
  }

  #visualIndex(index: number): number {
    return document.documentElement.dir === 'rtl' ? ITEMS.length - 1 - index : index
  }

  #isLiquidGlass(): boolean {
    const root = document.documentElement
    return root.dataset.floatingBottomBar === 'true' && root.dataset.liquidGlass === 'true'
  }
}

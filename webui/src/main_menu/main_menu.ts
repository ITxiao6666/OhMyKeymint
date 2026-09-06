import type { MdMenu } from '@material/web/all'
import { i18n } from '../i18n'
import './main_menu.scss'

export class MainMenu {
  #callbacks = new Map<string, Array<() => void>>()

  appendTo(container: HTMLElement): void {
    container.appendChild(this.#getElement(container))
  }

  on(event: string, callback: () => void): void {
    const callbacks = this.#callbacks.get(event) ?? []
    callbacks.push(callback)
    this.#callbacks.set(event, callbacks)
  }

  #getElement(container: HTMLElement): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-menu id="target-menu" anchor="menu-button">
        <md-menu-item id="select-all">
          <md-icon slot="start">select_all</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-menu-item id="deselect-all">
          <md-icon slot="start">deselect</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-menu-item id="refresh">
          <md-icon slot="start">refresh</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-divider role="separator" tabindex="-1"></md-divider>
        <md-menu-item id="add-system-app">
          <md-icon slot="start">apps</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
      </md-menu>
    `

    const fragment = template.content
    const menu = fragment.querySelector<MdMenu>('#target-menu')!
    const menuButton = container.querySelector<HTMLElement>('#menu-button')!
    let pendingAction: string | null = null
    const menuLabel = menuButton.querySelector<HTMLElement>('.targets-menu-label')
    const menuTitle = i18n.t('menu_more_options')
    if (menuLabel) menuLabel.textContent = menuTitle
    menuButton.title = menuTitle
    menuButton.setAttribute('aria-label', menuTitle)
    menuButton.setAttribute('aria-haspopup', 'menu')
    menuButton.setAttribute('aria-expanded', 'false')
    menuButton.onclick = () => { menu.open = !menu.open }

    const actions: Array<[string, string, string]> = [
      ['select-all', 'menu-select-all', i18n.t('menu_select_all')],
      ['deselect-all', 'menu-deselect-all', i18n.t('menu_deselect_all')],
      ['refresh', 'menu-refresh', i18n.t('menu_refresh')],
      ['add-system-app', 'menu-add-system-app', i18n.t('menu_add_system_app')],
    ]
    for (const [id, event, label] of actions) {
      const item = fragment.querySelector<HTMLElement>(`#${id}`)!
      item.querySelector<HTMLElement>('[slot="headline"]')!.textContent = label
      item.title = label
      item.setAttribute('aria-label', label)
      item.onclick = () => {
        pendingAction = event
        menu.open = false
      }
    }

    menu.addEventListener('opened', () => {
      menuButton.setAttribute('aria-expanded', 'true')
      this.#emit('menu-open')
    })
    menu.addEventListener('closed', () => {
      menuButton.setAttribute('aria-expanded', 'false')
      this.#emit('menu-close')
      if (pendingAction !== null) {
        const action = pendingAction
        pendingAction = null
        window.requestAnimationFrame(() => this.#emit(action))
      }
    })
    return fragment
  }

  #emit(event: string): void {
    this.#callbacks.get(event)?.forEach(callback => callback())
  }
}

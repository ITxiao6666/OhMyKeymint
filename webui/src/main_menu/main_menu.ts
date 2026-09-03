import type { MdIconButton, MdMenu, MdMenuItem, MdSubMenu } from '@material/web/all'
import { i18n } from '../i18n'
import './main_menu.scss'

export class MainMenu {
  #callbacks = new Map<string, Array<() => void>>()
  #securityPatchItems: Array<{
    item: HTMLElement
    icon: HTMLElement
  }> = []

  appendTo(container: HTMLElement): void {
    container.appendChild(this.#getElement(container))
  }

  #getElement(container: HTMLElement): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-menu id="menu-options" anchor="menu-button">
        <div class="menu-item-button-container">
          <md-filled-tonal-icon-button id="select-all"><md-icon>select_all</md-icon></md-filled-tonal-icon-button>
          <md-filled-tonal-icon-button id="deselect-all"><md-icon>deselect</md-icon></md-filled-tonal-icon-button>
          <md-filled-tonal-icon-button id="refresh"><md-icon>refresh</md-icon></md-filled-tonal-icon-button>
        </div>
        <md-divider role="separator" tabindex="-1"></md-divider>
        <md-menu-item id="add-system-app">
          <md-icon slot="start">apps</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-menu-item id="install-keybox">
          <md-icon slot="start">upload_file</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-menu-item id="sync-security-patch">
          <md-icon class="menu-action-icon" slot="start">security_update</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-menu-item id="restore-default-security-patch">
          <md-icon class="menu-action-icon" slot="start">settings_backup_restore</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-menu-item id="spoof-pif-fingerprint">
          <md-icon slot="start">fingerprint</md-icon>
          <div slot="headline"></div>
        </md-menu-item>
        <md-divider role="separator" tabindex="-1"></md-divider>
        <md-sub-menu hover-close-delay="0">
          <md-menu-item slot="item" class="sub-menu-entry">
            <div slot="headline"></div>
            <md-icon slot="end">language</md-icon>
          </md-menu-item>
          <md-menu positioning="popover" slot="menu" id="language-menu" x-offset="2"></md-menu>
        </md-sub-menu>
      </md-menu>
    `

    const fragment = template.content
    const menuOptions = fragment.querySelector<MdMenu>('#menu-options')!
    const menuButton = container.querySelector<MdIconButton>('#menu-button')!
    menuButton.title = i18n.t('menu_more_options')
    menuButton.onclick = () => { menuOptions.open = !menuOptions.open }

    this.#setHeadline(fragment, '#add-system-app', i18n.t('menu_add_system_app'))
    this.#setHeadline(fragment, '#install-keybox', i18n.t('menu_replace_keybox'))
    this.#setHeadline(fragment, '#sync-security-patch', i18n.t('menu_sync_security_patch'))
    this.#setHeadline(fragment, '#restore-default-security-patch', i18n.t('menu_restore_default_security_patch'))
    this.#setHeadline(fragment, '#spoof-pif-fingerprint', i18n.t('menu_spoof_pif_fingerprint'))
    this.#setHeadline(fragment, '.sub-menu-entry', i18n.t('menu_language'))

    this.#securityPatchItems = ['sync-security-patch', 'restore-default-security-patch']
      .map(id => {
        const item = fragment.querySelector<HTMLElement>(`#${id}`)
        const icon = item?.querySelector<HTMLElement>('.menu-action-icon')
        if (!item || !icon) return null
        return { item, icon }
      })
      .filter((entry): entry is {
        item: HTMLElement
        icon: HTMLElement
      } => entry !== null)

    const actions: Array<[string, string, string]> = [
      ['select-all', 'menu-select-all', i18n.t('menu_select_all')],
      ['deselect-all', 'menu-deselect-all', i18n.t('menu_deselect_all')],
      ['refresh', 'menu-refresh', i18n.t('menu_refresh')],
      ['add-system-app', 'menu-add-system-app', i18n.t('menu_add_system_app')],
      ['install-keybox', 'menu-install-keybox', i18n.t('menu_replace_keybox')],
      ['sync-security-patch', 'menu-sync-security-patch', i18n.t('menu_sync_security_patch')],
      ['restore-default-security-patch', 'menu-restore-default-security-patch', i18n.t('menu_restore_default_security_patch')],
      ['spoof-pif-fingerprint', 'menu-spoof-pif-fingerprint', i18n.t('menu_spoof_pif_fingerprint')],
    ]
    for (const [id, event, label] of actions) {
      const item = fragment.querySelector<HTMLElement>(`#${id}`)!
      item.title = label
      item.setAttribute('aria-label', label)
      item.onclick = () => {
        if (item.hasAttribute('disabled')) return
        this.#emit(event)
        menuOptions.open = false
      }
    }

    menuOptions.addEventListener('opened', () => this.#emit('menu-open'))
    menuOptions.addEventListener('closed', () => this.#emit('menu-close'))

    let subMenuOpen = false
    fragment.querySelectorAll<MdMenuItem>('.sub-menu-entry').forEach(item => {
      const subMenu = item.parentElement as MdSubMenu
      item.onclick = event => {
        event.stopPropagation()
        subMenuOpen = !subMenuOpen
        if (subMenuOpen) subMenu.show()
        else subMenu.close()
      }
      subMenu.querySelector('md-menu')?.addEventListener('opening', () => { subMenuOpen = true })
      subMenu.querySelector('md-menu')?.addEventListener('closing', () => { subMenuOpen = false })
    })

    const languageMenu = fragment.querySelector<MdMenu>('#language-menu')!
    languageMenu.setAttribute('aria-label', i18n.t('menu_language'))
    const languages = { default: i18n.t('system_default'), ...i18n.languages }
    for (const [code, name] of Object.entries(languages)) {
      const item = document.createElement('md-menu-item')
      item.id = `lang-${code}`
      const selected = i18n.preference === code
      item.selected = selected
      if (selected) {
        item.setAttribute('selected', '')
        item.setAttribute('aria-selected', 'true')
      } else item.setAttribute('aria-selected', 'false')
      item.setAttribute('aria-label', name)
      item.dataset.language = code

      const headline = document.createElement('div')
      headline.setAttribute('slot', 'headline')
      headline.textContent = name
      item.appendChild(headline)

      const check = document.createElement('md-icon')
      check.className = 'language-check'
      check.setAttribute('slot', 'end')
      check.textContent = 'check'
      check.hidden = !selected
      check.setAttribute('aria-hidden', 'true')
      item.appendChild(check)

      item.onclick = () => {
        languageMenu.close()
        i18n.setLanguage(code)
      }
      languageMenu.appendChild(item)
    }

    return fragment
  }

  /** Show or hide the progress indicator for both security-patch actions. */
  setSecurityPatchBusy(busy: boolean): void {
    for (const { item, icon } of this.#securityPatchItems) {
      item.toggleAttribute('disabled', busy)
      item.toggleAttribute('aria-busy', busy)
      icon.toggleAttribute('hidden', busy)

      const progress = item.querySelector<HTMLElement>('.menu-action-progress')
      if (busy) {
        if (!progress) {
          const indicator = document.createElement('md-circular-progress')
          indicator.className = 'menu-action-progress'
          indicator.setAttribute('slot', 'start')
          indicator.setAttribute('indeterminate', '')
          indicator.setAttribute('aria-hidden', 'true')
          item.appendChild(indicator)
        }
      } else {
        progress?.remove()
      }
    }
  }

  #setHeadline(root: ParentNode, selector: string, value: string): void {
    const headline = root.querySelector<HTMLElement>(`${selector} [slot="headline"]`)
    if (headline) headline.textContent = value
  }

  on(event: string, callback: () => void): void {
    const callbacks = this.#callbacks.get(event) ?? []
    callbacks.push(callback)
    this.#callbacks.set(event, callbacks)
  }

  #emit(event: string): void {
    this.#callbacks.get(event)?.forEach(callback => callback())
  }
}

import type { MdOutlinedTextField } from '@material/web/all'
import type { AppList, SelectionFilter } from '../app_list/app_list'
import { i18n } from '../i18n'
import { MainMenu } from '../main_menu/main_menu'
import './pages.scss'

export type TargetPageEvent =
  | 'target-close'
  | 'target-apply'
  | 'target-select-all'
  | 'target-deselect-all'
  | 'target-refresh'
  | 'target-add-system-app'

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

export class AppTargetsPage {
  readonly #appList: AppList
  #element: HTMLElement | null = null
  #searchField: MdOutlinedTextField | null = null
  #callbacks = new Map<TargetPageEvent, Array<() => void>>()
  #filter: SelectionFilter = 'all'

  constructor(appList: AppList) {
    this.#appList = appList
  }

  getElement(): HTMLElement {
    const page = document.createElement('section')
    page.id = 'page-targets'
    page.className = 'targets-page targets-overlay'
    page.hidden = true
    page.innerHTML = /* html */ `
      <header class="targets-heading">
        <md-icon-button class="targets-back" flip-icon-in-rtl="true">
          <md-icon>arrow_back</md-icon>
        </md-icon-button>
        <h1></h1>
        <div class="main-menu">
          <button id="menu-button" class="targets-menu-button" type="button">
            <md-icon aria-hidden="true">more_vert</md-icon>
            <span class="targets-menu-label"></span>
          </button>
        </div>
      </header>
      <div class="targets-controls">
        <md-outlined-text-field class="targets-search">
          <md-icon slot="leading-icon">search</md-icon>
          <md-icon-button class="targets-search-clear" slot="trailing-icon" hidden>
            <md-icon>close</md-icon>
          </md-icon-button>
        </md-outlined-text-field>
        <div class="targets-filters" role="radiogroup"></div>
      </div>
      <div class="app-list">
        <div class="loading"><md-circular-progress indeterminate></md-circular-progress></div>
      </div>
      <md-fab variant="primary" class="targets-apply">
        <md-icon slot="icon">check</md-icon>
      </md-fab>
    `

    page.querySelector<HTMLElement>('.targets-heading h1')!.textContent =
      translate('app_targets_title', 'App targets')
    const backButton = page.querySelector<HTMLElement>('.targets-back')!
    backButton.setAttribute('aria-label', translate('functional_button_back', 'Back'))
    backButton.onclick = () => this.#emit('target-close')
    const applyButton = page.querySelector<HTMLElement>('.targets-apply')!
    applyButton.setAttribute('label', translate('functional_button_apply', 'Apply'))
    applyButton.onclick = () => this.#emit('target-apply')
    this.#searchField = page.querySelector<MdOutlinedTextField>('.targets-search')!
    this.#searchField.placeholder = i18n.t('search_bar_search_placeholder')
    const clearButton = page.querySelector<HTMLElement>('.targets-search-clear')!
    clearButton.setAttribute('aria-label', i18n.t('functional_button_close'))
    this.#searchField.addEventListener('input', () => {
      const query = this.#searchField?.value ?? ''
      clearButton.toggleAttribute('hidden', query.length === 0)
      this.#appList.setSearchQuery(query)
    })
    clearButton.onclick = () => {
      if (!this.#searchField) return
      this.#searchField.value = ''
      clearButton.setAttribute('hidden', '')
      this.#appList.setSearchQuery('')
      this.#searchField.focus()
    }

    const filters = page.querySelector<HTMLElement>('.targets-filters')!
    filters.setAttribute('aria-label', translate('app_targets_filter_aria', 'Filter apps'))
    filters.append(
      this.#createFilter('all', 'select_all', translate('filter_all', 'All')),
      this.#createFilter('selected', 'check_circle', translate('filter_selected', 'Selected')),
      this.#createFilter('unselected', 'radio_button_unchecked', translate('filter_unselected', 'Not selected')),
    )

    const menu = new MainMenu()
    menu.appendTo(page.querySelector<HTMLElement>('.main-menu')!)
    menu.on('menu-open', () => { this.#appList.menuOpen = true })
    menu.on('menu-close', () => { this.#appList.menuOpen = false })
    menu.on('menu-select-all', () => this.#emit('target-select-all'))
    menu.on('menu-deselect-all', () => this.#emit('target-deselect-all'))
    menu.on('menu-refresh', () => this.#emit('target-refresh'))
    menu.on('menu-add-system-app', () => this.#emit('target-add-system-app'))

    this.#element = page
    this.#syncFilters()
    return page
  }

  get listContainer(): HTMLElement {
    const container = this.#element?.querySelector<HTMLElement>('.app-list')
    if (!container) throw new Error('App target page is not mounted')
    return container
  }

  on(event: TargetPageEvent, callback: () => void): void {
    const callbacks = this.#callbacks.get(event) ?? []
    callbacks.push(callback)
    this.#callbacks.set(event, callbacks)
  }

  show(): void {
    if (!this.#element || !this.#element.hidden) return
    this.#element.hidden = false
    requestAnimationFrame(() => this.#element?.classList.add('open'))
  }

  close(): void {
    if (!this.#element || this.#element.hidden) return
    this.#element.querySelectorAll('md-menu').forEach(menu => menu.close())
    this.#appList.menuOpen = false
    this.#element.classList.remove('open')
    window.setTimeout(() => {
      if (this.#element && !this.#element.classList.contains('open')) this.#element.hidden = true
    }, 220)
  }

  setApplyEnabled(enabled: boolean): void {
    const button = this.#element?.querySelector<HTMLElement>('.targets-apply')
    button?.toggleAttribute('disabled', !enabled)
  }

  focusSearch(): void {
    this.#searchField?.focus()
  }

  #createFilter(filter: SelectionFilter, iconName: string, label: string): HTMLButtonElement {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'target-filter'
    button.dataset.filter = filter
    button.setAttribute('role', 'radio')
    const icon = document.createElement('md-icon')
    icon.textContent = iconName
    icon.setAttribute('aria-hidden', 'true')
    const text = document.createElement('span')
    text.textContent = label
    button.append(icon, text)
    button.onclick = () => {
      this.#filter = filter
      this.#appList.setSelectionFilter(filter)
      this.#syncFilters()
    }
    return button
  }

  #syncFilters(): void {
    this.#element?.querySelectorAll<HTMLElement>('.target-filter').forEach(button => {
      const selected = button.dataset.filter === this.#filter
      button.classList.toggle('selected', selected)
      button.setAttribute('aria-checked', String(selected))
    })
  }

  #emit(event: TargetPageEvent): void {
    this.#callbacks.get(event)?.forEach(callback => callback())
  }
}

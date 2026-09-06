import type { MdMenu, MdMenuItem } from '@material/web/all'
import {
  APPEARANCE_MODES,
  type AccentColor,
  type AppearanceController,
  type AppearanceMode,
} from '../appearance'
import { i18n } from '../i18n'
import './pages.scss'

interface ModeDefinition {
  value: AppearanceMode
  icon: string
  labelKey: string
  fallback: string
}

interface AccentDefinition {
  value: AccentColor
  labelKey: string
  fallback: string
}

const MODES: readonly ModeDefinition[] = [
  { value: 'dark', icon: 'dark_mode', labelKey: 'theme_mode_dark', fallback: 'Dark' },
  { value: 'amoled', icon: 'contrast', labelKey: 'theme_mode_amoled', fallback: 'AMOLED' },
  { value: 'light', icon: 'light_mode', labelKey: 'theme_mode_light', fallback: 'Light' },
  { value: 'auto', icon: 'brightness_auto', labelKey: 'theme_mode_auto', fallback: 'Auto' },
]

const ACCENTS: readonly AccentDefinition[] = [
  { value: 'blue', labelKey: 'theme_color_blue', fallback: 'Blue' },
  { value: 'yellow', labelKey: 'theme_color_yellow', fallback: 'Yellow' },
  { value: 'red', labelKey: 'theme_color_red', fallback: 'Red' },
  { value: 'purple', labelKey: 'theme_color_purple', fallback: 'Purple' },
  { value: 'green', labelKey: 'theme_color_green', fallback: 'Green' },
  { value: 'orange', labelKey: 'theme_color_orange', fallback: 'Orange' },
  { value: 'pink', labelKey: 'theme_color_pink', fallback: 'Pink' },
  { value: 'cyan', labelKey: 'theme_color_cyan', fallback: 'Cyan' },
  { value: 'grey', labelKey: 'theme_color_grey', fallback: 'Grey' },
  { value: 'system', labelKey: 'theme_color_system', fallback: 'System' },
]

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

export class SettingsPage {
  #element: HTMLElement | null = null

  constructor(private readonly appearance: AppearanceController) {}

  getElement(): HTMLElement {
    const page = document.createElement('section')
    page.id = 'page-settings'
    page.className = 'app-page settings-page'
    page.dataset.page = 'settings'
    page.hidden = true

    const heading = document.createElement('header')
    heading.className = 'page-heading'
    const title = document.createElement('h1')
    title.textContent = translate('settings_title', 'Settings')
    heading.appendChild(title)

    page.append(heading, this.#createLanguageSection(), this.#createAppearanceSection())
    this.#element = page
    this.appearance.onChange(() => this.#syncAppearanceControls())
    this.#syncAppearanceControls()
    return page
  }

  #createLanguageSection(): HTMLElement {
    const title = translate('settings_language', 'Language')
    const section = this.#createSection(title, 'settings-language-section')
    const row = document.createElement('div')
    row.className = 'settings-select-row'

    const icon = document.createElement('md-icon')
    icon.textContent = 'language'
    icon.setAttribute('aria-hidden', 'true')

    const field = document.createElement('div')
    field.className = 'settings-select-field'
    const languages: Record<string, string> = {
      default: translate('settings_language_auto', 'Auto'),
      ...i18n.languages,
    }

    const trigger = document.createElement('button')
    trigger.type = 'button'
    trigger.className = 'settings-language-trigger'
    trigger.setAttribute('aria-label', title)
    trigger.setAttribute('aria-haspopup', 'listbox')
    trigger.setAttribute('aria-expanded', 'false')
    const currentLanguage = document.createElement('span')
    currentLanguage.className = 'settings-language-current'
    currentLanguage.textContent = languages[i18n.preference] ?? languages.default
    const arrow = document.createElement('md-icon')
    arrow.textContent = 'expand_more'
    arrow.setAttribute('aria-hidden', 'true')
    trigger.append(currentLanguage, arrow)

    const menu = document.createElement('md-menu') as MdMenu
    menu.className = 'settings-language-menu'
    menu.anchorElement = trigger
    menu.defaultFocus = 'none'
    menu.setAttribute('role', 'listbox')
    menu.setAttribute('aria-label', title)

    for (const [code, name] of Object.entries(languages)) {
      const option = document.createElement('md-menu-item') as MdMenuItem
      const selected = i18n.preference === code
      option.type = 'option'
      option.className = 'settings-language-option'
      option.classList.toggle('current', selected)
      option.dataset.language = code
      option.setAttribute('aria-selected', String(selected))

      const label = document.createElement('span')
      label.slot = 'headline'
      label.className = 'settings-language-name'
      label.textContent = name
      if (code !== 'default') label.lang = code

      const check = document.createElement('md-icon')
      check.slot = 'end'
      check.className = 'settings-language-check'
      check.textContent = 'check'
      check.setAttribute('aria-hidden', 'true')
      option.append(label, check)
      option.onclick = () => {
        menu.open = false
        if (i18n.preference !== code) i18n.setLanguage(code)
      }
      menu.appendChild(option)
    }

    trigger.onclick = () => { menu.open = !menu.open }
    trigger.onkeydown = event => {
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
      event.preventDefault()
      menu.open = true
    }
    menu.addEventListener('opening', () => {
      trigger.setAttribute('aria-expanded', 'true')
      trigger.classList.add('open')
    })
    menu.addEventListener('opened', () => {
      const selected = menu.querySelector<HTMLElement>('.settings-language-option.current')
      const scroller = menu.shadowRoot?.querySelector<HTMLElement>('.items')
      if (selected && scroller) {
        scroller.scrollTop = Math.max(
          0,
          selected.offsetTop - ((scroller.clientHeight - selected.offsetHeight) / 2),
        )
        selected.focus({ preventScroll: true })
      }
    })
    menu.addEventListener('closed', () => {
      trigger.setAttribute('aria-expanded', 'false')
      trigger.classList.remove('open')
    })

    field.append(trigger, menu)
    row.append(icon, field)
    section.appendChild(row)
    return section
  }

  #createAppearanceSection(): HTMLElement {
    const section = this.#createSection(
      translate('settings_appearance', 'Appearance'),
      'settings-appearance-section',
    )
    const modeTitle = document.createElement('h3')
    modeTitle.className = 'settings-sublabel'
    modeTitle.textContent = translate('settings_mode', 'Mode')
    const modes = document.createElement('div')
    modes.className = 'appearance-mode-group'
    modes.setAttribute('role', 'radiogroup')
    modes.setAttribute('aria-label', modeTitle.textContent)
    for (const definition of MODES) modes.appendChild(this.#createModeButton(definition))

    const divider = document.createElement('div')
    divider.className = 'settings-divider'
    divider.setAttribute('aria-hidden', 'true')

    const colorTitle = document.createElement('h3')
    colorTitle.className = 'settings-sublabel'
    colorTitle.textContent = translate('settings_color', 'Color')
    const colors = document.createElement('div')
    colors.className = 'appearance-color-group'
    const trigger = document.createElement('button')
    trigger.type = 'button'
    trigger.className = 'settings-language-trigger appearance-color-trigger'
    trigger.setAttribute('aria-label', colorTitle.textContent)
    trigger.setAttribute('aria-haspopup', 'listbox')
    trigger.setAttribute('aria-expanded', 'false')
    const currentSwatch = document.createElement('span')
    currentSwatch.className = 'settings-color-swatch'
    const current = document.createElement('span')
    current.className = 'settings-language-current'
    const arrow = document.createElement('md-icon')
    arrow.textContent = 'expand_more'
    trigger.append(currentSwatch, current, arrow)
    const menu = document.createElement('md-menu') as MdMenu
    menu.className = 'settings-language-menu appearance-color-menu'
    menu.anchorElement = trigger
    menu.defaultFocus = 'none'
    menu.noVerticalFlip = true
    menu.setAttribute('role', 'listbox')
    menu.setAttribute('aria-label', colorTitle.textContent)
    for (const definition of ACCENTS) {
      const option = document.createElement('md-menu-item') as MdMenuItem
      option.type = 'option'
      option.className = 'settings-language-option appearance-color-option'
      option.dataset.accent = definition.value
      option.setAttribute('role', 'option')
      option.setAttribute('aria-selected', 'false')
      const swatch = document.createElement('span')
      swatch.slot = 'start'
      swatch.className = `settings-color-swatch accent-${definition.value}`
      const label = document.createElement('span')
      label.slot = 'headline'
      label.textContent = translate(definition.labelKey, definition.fallback)
      const check = document.createElement('md-icon')
      check.slot = 'end'
      check.className = 'settings-language-check'
      check.textContent = 'check'
      option.append(swatch, label, check)
      option.onclick = () => { menu.open = false; this.appearance.setAccent(definition.value) }
      menu.appendChild(option)
    }
    trigger.onclick = () => { menu.open = !menu.open }
    menu.addEventListener('opening', () => { trigger.setAttribute('aria-expanded', 'true'); trigger.classList.add('open') })
    menu.addEventListener('opened', () => {
      const selected = menu.querySelector<HTMLElement>('.appearance-color-menu md-menu-item.current')
      selected?.focus({ preventScroll: true })
    })
    menu.addEventListener('closed', () => { trigger.setAttribute('aria-expanded', 'false'); trigger.classList.remove('open') })
    colors.append(trigger, menu)

    section.append(modeTitle, modes, divider, colorTitle, colors)
    return section
  }

  #createSection(title: string, className: string): HTMLElement {
    const section = document.createElement('section')
    section.className = `feature-section settings-section ${className}`
    const heading = document.createElement('h2')
    heading.className = 'section-title settings-section-title'
    heading.textContent = title
    section.appendChild(heading)
    return section
  }

  #createModeButton(definition: ModeDefinition): HTMLButtonElement {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'appearance-mode-button'
    button.dataset.mode = definition.value
    button.setAttribute('role', 'radio')
    const label = translate(definition.labelKey, definition.fallback)
    button.title = label
    button.setAttribute('aria-label', label)

    const check = document.createElement('md-icon')
    check.className = 'appearance-selected-icon'
    check.textContent = 'check'
    check.setAttribute('aria-hidden', 'true')
    const icon = document.createElement('md-icon')
    icon.textContent = definition.icon
    icon.setAttribute('aria-hidden', 'true')
    button.append(check, icon)
    button.onclick = () => this.appearance.setMode(definition.value)
    button.onkeydown = event => this.#handleRadioKey(
      event,
      APPEARANCE_MODES,
      definition.value,
      mode => this.appearance.setMode(mode),
    )
    return button
  }

  #handleRadioKey<T extends string>(
    event: KeyboardEvent,
    values: readonly T[],
    current: T,
    select: (value: T) => void,
  ): void {
    const rtl = document.documentElement.dir === 'rtl'
    let nextIndex: number | null = null
    const currentIndex = values.indexOf(current)
    if (event.key === 'Home') nextIndex = 0
    else if (event.key === 'End') nextIndex = values.length - 1
    else if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      const direction = event.key === 'ArrowRight' && rtl ? -1 : 1
      nextIndex = (currentIndex + direction + values.length) % values.length
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      const direction = event.key === 'ArrowLeft' && rtl ? 1 : -1
      nextIndex = (currentIndex + direction + values.length) % values.length
    }
    if (nextIndex === null) return
    event.preventDefault()
    select(values[nextIndex]!)
    window.requestAnimationFrame(() => {
      const value = values[nextIndex!]
      this.#element
        ?.querySelector<HTMLElement>(`[data-mode="${value}"], [data-accent="${value}"]`)
        ?.focus()
    })
  }

  #syncAppearanceControls(): void {
    this.#element?.querySelectorAll<HTMLButtonElement>('[data-mode]').forEach(button => {
      const selected = button.dataset.mode === this.appearance.mode
      button.classList.toggle('selected', selected)
      button.setAttribute('aria-checked', String(selected))
      button.tabIndex = selected ? 0 : -1
    })
    const colorTrigger = this.#element?.querySelector<HTMLElement>('.appearance-color-trigger .settings-language-current')
    const colorSwatch = this.#element?.querySelector<HTMLElement>('.appearance-color-trigger .settings-color-swatch')
    if (colorTrigger) {
      const definition = ACCENTS.find(item => item.value === this.appearance.accent)
      colorTrigger.textContent = definition
        ? translate(definition.labelKey, definition.fallback)
        : this.appearance.accent
      if (colorSwatch) colorSwatch.className = `settings-color-swatch accent-${this.appearance.accent}`
    }
    this.#element?.querySelectorAll<HTMLElement>('.appearance-color-menu md-menu-item').forEach(item => {
      const selected = item.dataset.accent === this.appearance.accent
      item.classList.toggle('current', selected)
      item.setAttribute('aria-selected', String(selected))
    })
  }
}

import type { MdMenu, MdMenuItem } from '@material/web/all'
import {
  APPEARANCE_MODES,
  type AccentColor,
  type AppearanceController,
  type AppearanceMode,
  type AppearanceOption,
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

interface ToggleDefinition {
  value: AppearanceOption
  icon: string
  labelKey: string
  labelFallback: string
  descriptionKey: string
  descriptionFallback: string
}

type SwitchElement = HTMLElement & { selected: boolean }

const MODES: readonly ModeDefinition[] = [
  { value: 'auto', icon: 'brightness_auto', labelKey: 'theme_mode_auto', fallback: 'Follow system' },
  { value: 'light', icon: 'light_mode', labelKey: 'theme_mode_light', fallback: 'Light' },
  { value: 'dark', icon: 'dark_mode', labelKey: 'theme_mode_dark', fallback: 'Dark' },
  { value: 'amoled', icon: 'contrast', labelKey: 'theme_mode_amoled', fallback: 'AMOLED' },
]

const ACCENTS: readonly AccentDefinition[] = [
  { value: 'default', labelKey: 'theme_color_default', fallback: 'Default' },
  { value: 'red', labelKey: 'theme_color_red', fallback: 'Red' },
  { value: 'pink', labelKey: 'theme_color_pink', fallback: 'Pink' },
  { value: 'purple', labelKey: 'theme_color_purple', fallback: 'Purple' },
  { value: 'deepPurple', labelKey: 'theme_color_deep_purple', fallback: 'Deep Purple' },
  { value: 'indigo', labelKey: 'theme_color_indigo', fallback: 'Indigo' },
  { value: 'blue', labelKey: 'theme_color_blue', fallback: 'Blue' },
  { value: 'cyan', labelKey: 'theme_color_cyan', fallback: 'Cyan' },
  { value: 'teal', labelKey: 'theme_color_teal', fallback: 'Teal' },
  { value: 'green', labelKey: 'theme_color_green', fallback: 'Green' },
  { value: 'yellow', labelKey: 'theme_color_yellow', fallback: 'Yellow' },
  { value: 'amber', labelKey: 'theme_color_amber', fallback: 'Amber' },
  { value: 'orange', labelKey: 'theme_color_orange', fallback: 'Orange' },
  { value: 'brown', labelKey: 'theme_color_brown', fallback: 'Brown' },
  { value: 'blueGrey', labelKey: 'theme_color_blue_grey', fallback: 'Blue Grey' },
  { value: 'sakura', labelKey: 'theme_color_sakura', fallback: 'Sakura' },
]

const MONET: ToggleDefinition = {
  value: 'monet',
  icon: 'wallpaper',
  labelKey: 'settings_monet',
  labelFallback: 'Monet system colors',
  descriptionKey: 'settings_monet_desc',
  descriptionFallback: 'Use the system wallpaper colors when available',
}

const EFFECTS: readonly ToggleDefinition[] = [
  {
    value: 'barBlur',
    icon: 'blur_on',
    labelKey: 'settings_bar_blur',
    labelFallback: 'Bar blur',
    descriptionKey: 'settings_bar_blur_desc',
    descriptionFallback: 'Blur content behind the top and bottom bars',
  },
  {
    value: 'floatingBottomBar',
    icon: 'bottom_navigation',
    labelKey: 'settings_floating_bottom_bar',
    labelFallback: 'Floating bottom bar',
    descriptionKey: 'settings_floating_bottom_bar_desc',
    descriptionFallback: 'Show navigation as a compact floating bar',
  },
  {
    value: 'liquidGlass',
    icon: 'water_drop',
    labelKey: 'settings_liquid_glass',
    labelFallback: 'Liquid glass',
    descriptionKey: 'settings_liquid_glass_desc',
    descriptionFallback: 'Add translucent glass depth to the floating bar',
  },
]

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

/**
 * Material Web keeps the actual menu scroller in its shadow tree. Styling the
 * host is not enough on older Android WebViews, so apply the same scrollbar
 * policy to the internal list once the menu has rendered.
 */
function hideMenuScrollbar(menu: MdMenu): void {
  const shadow = menu.shadowRoot
  const scroller = shadow?.querySelector<HTMLElement>('.items')
  if (scroller) {
    scroller.style.scrollbarWidth = 'none'
    scroller.style.setProperty('-ms-overflow-style', 'none')
  }
  if (!shadow || shadow.querySelector('style[data-omk-scrollbar]')) return
  const style = document.createElement('style')
  style.dataset.omkScrollbar = ''
  style.textContent = '.items::-webkit-scrollbar{width:0;height:0;display:none}'
  shadow.appendChild(style)
}

export class SettingsPage {
  #element: HTMLElement | null = null

  constructor(private readonly appearance: AppearanceController) {}

  getElement(): HTMLElement {
    const page = document.createElement('section')
    page.id = 'page-settings'
    page.className = 'app-page miuix-page settings-page'
    page.dataset.page = 'settings'
    page.hidden = true

    const heading = document.createElement('header')
    heading.className = 'page-heading miuix-top-app-bar'
    const title = document.createElement('h1')
    title.textContent = translate('settings_title', 'Settings')
    heading.appendChild(title)

    page.append(
      heading,
      this.#createPreview(),
      this.#createLanguageSection(),
      this.#createAppearanceSection(),
      this.#createEffectsSection(),
    )
    this.#element = page
    this.appearance.onChange(() => this.#syncAppearanceControls())
    this.#syncAppearanceControls()
    return page
  }

  #createPreview(): HTMLElement {
    const section = document.createElement('section')
    section.className = 'settings-preview-section'

    const heading = document.createElement('h2')
    heading.className = 'settings-section-title settings-preview-title'
    heading.textContent = translate('settings_preview', 'Theme preview')

    const preview = document.createElement('div')
    preview.className = 'settings-theme-preview'
    preview.setAttribute('aria-hidden', 'true')
    preview.innerHTML = /* html */ `
      <div class="settings-preview-device">
        <div class="settings-preview-top-bar">
          <span class="settings-preview-avatar"></span>
          <span class="settings-preview-title-line"></span>
          <span class="settings-preview-action"></span>
        </div>
        <div class="settings-preview-content">
          <span class="settings-preview-card settings-preview-card-primary"></span>
          <span class="settings-preview-card"></span>
          <span class="settings-preview-card"></span>
        </div>
        <div class="settings-preview-nav">
          <span class="settings-preview-nav-item active"></span>
          <span class="settings-preview-nav-item"></span>
          <span class="settings-preview-nav-item"></span>
        </div>
      </div>
    `
    section.append(heading, preview)
    return section
  }

  #createLanguageSection(): HTMLElement {
    const title = translate('settings_language', 'Language')
    const section = this.#createSection(title, 'settings-language-section')
    const row = document.createElement('div')
    row.className = 'settings-select-row settings-language-row miuix-preference'

    const icon = this.#createPreferenceIcon('language')

    const field = document.createElement('div')
    field.className = 'settings-select-field'
    const languages: Record<string, string> = {
      default: translate('settings_language_auto', 'Follow system'),
      ...i18n.languages,
    }

    const trigger = document.createElement('button')
    trigger.type = 'button'
    trigger.className = 'settings-language-trigger miuix-dropdown-preference'
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
      hideMenuScrollbar(menu)
      trigger.setAttribute('aria-expanded', 'true')
      trigger.classList.add('open')
    })
    menu.addEventListener('opened', () => {
      hideMenuScrollbar(menu)
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

    const modeBlock = document.createElement('div')
    modeBlock.className = 'settings-mode-block'
    const modeTitle = document.createElement('h3')
    modeTitle.className = 'settings-sublabel'
    modeTitle.textContent = translate('settings_mode', 'Mode')
    const modes = document.createElement('div')
    modes.className = 'appearance-mode-group miuix-tab-row'
    modes.setAttribute('role', 'radiogroup')
    modes.setAttribute('aria-label', modeTitle.textContent)
    for (const definition of MODES) modes.appendChild(this.#createModeButton(definition))
    modeBlock.append(modeTitle, modes)

    section.append(
      modeBlock,
      this.#createDivider(),
      this.#createToggleRow(MONET),
      this.#createColorSelector(),
    )
    return section
  }

  #createEffectsSection(): HTMLElement {
    const section = this.#createSection(
      translate('settings_effects', 'Visual effects'),
      'settings-effects-section',
    )
    for (const definition of EFFECTS) section.appendChild(this.#createToggleRow(definition))
    return section
  }

  #createColorSelector(): HTMLElement {
    const title = translate('settings_color', 'Accent color')
    const row = document.createElement('div')
    row.className = 'settings-preference-row settings-color-row miuix-preference'
    row.appendChild(this.#createPreferenceIcon('colorize'))

    const field = document.createElement('div')
    field.className = 'settings-select-field settings-color-field'
    const trigger = document.createElement('button')
    trigger.type = 'button'
    trigger.className = 'settings-choice-trigger appearance-color-trigger'
    trigger.setAttribute('aria-label', title)
    trigger.setAttribute('aria-haspopup', 'listbox')
    trigger.setAttribute('aria-expanded', 'false')

    const copy = document.createElement('span')
    copy.className = 'settings-preference-copy'
    const label = document.createElement('span')
    label.className = 'settings-preference-title'
    label.textContent = title
    copy.appendChild(label)

    const current = document.createElement('span')
    current.className = 'settings-language-current settings-choice-current'
    const arrow = document.createElement('md-icon')
    arrow.textContent = 'unfold_more'
    arrow.setAttribute('aria-hidden', 'true')
    trigger.append(copy, current, arrow)

    const menu = document.createElement('md-menu') as MdMenu
    menu.className = 'settings-language-menu appearance-color-menu'
    menu.anchorElement = trigger
    menu.defaultFocus = 'none'
    menu.positioning = 'fixed'
    menu.anchorCorner = 'end-end'
    menu.menuCorner = 'start-end'
    menu.setAttribute('role', 'listbox')
    menu.setAttribute('aria-label', title)

    const scrim = document.createElement('div')
    scrim.className = 'appearance-color-scrim'
    scrim.setAttribute('aria-hidden', 'true')
    scrim.onclick = () => { menu.open = false }

    for (const definition of ACCENTS) {
      const option = document.createElement('md-menu-item') as MdMenuItem
      option.type = 'option'
      option.className = 'settings-language-option appearance-color-option'
      option.dataset.accent = definition.value
      option.setAttribute('role', 'option')
      option.setAttribute('aria-selected', 'false')
      const optionLabel = document.createElement('span')
      optionLabel.slot = 'headline'
      optionLabel.textContent = translate(definition.labelKey, definition.fallback)
      const check = document.createElement('md-icon')
      check.slot = 'end'
      check.className = 'settings-language-check'
      check.textContent = 'check'
      check.setAttribute('aria-hidden', 'true')
      option.append(optionLabel, check)
      option.onclick = () => {
        menu.open = false
        this.appearance.setAccent(definition.value)
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
      hideMenuScrollbar(menu)
      trigger.setAttribute('aria-expanded', 'true')
      trigger.classList.add('open')
      scrim.classList.add('visible')
    })
    menu.addEventListener('opened', () => {
      hideMenuScrollbar(menu)
      menu.querySelector<HTMLElement>('.appearance-color-option.current')
        ?.focus({ preventScroll: true })
    })
    menu.addEventListener('closed', () => {
      trigger.setAttribute('aria-expanded', 'false')
      trigger.classList.remove('open')
      scrim.classList.remove('visible')
    })
    field.append(trigger, scrim, menu)
    row.appendChild(field)
    return row
  }

  #createToggleRow(definition: ToggleDefinition): HTMLElement {
    const row = document.createElement('div')
    row.className = 'settings-preference-row settings-toggle-row miuix-preference'
    row.dataset.appearanceRow = definition.value
    row.appendChild(this.#createPreferenceIcon(definition.icon))

    const copy = document.createElement('span')
    copy.className = 'settings-preference-copy'
    const title = document.createElement('span')
    title.className = 'settings-preference-title'
    title.textContent = translate(definition.labelKey, definition.labelFallback)
    const description = document.createElement('span')
    description.className = 'settings-preference-description'
    description.textContent = translate(
      definition.descriptionKey,
      definition.descriptionFallback,
    )
    copy.append(title, description)

    const toggle = document.createElement('md-switch') as SwitchElement
    toggle.dataset.appearanceOption = definition.value
    toggle.setAttribute('aria-label', title.textContent)
    const syncOption = (): void => {
      this.appearance.setOption(definition.value, toggle.selected)
    }
    // Material Web emits `input` as the composed event and redispatches
    // `change` for compatibility. Listening to both keeps Android WebViews
    // reliable while AppearanceController's no-op guard avoids duplicate work.
    toggle.addEventListener('input', syncOption)
    toggle.addEventListener('change', syncOption)
    row.addEventListener('click', event => {
      if (toggle.contains(event.target as Node)) return
      toggle.selected = !toggle.selected
      this.appearance.setOption(definition.value, toggle.selected)
    })
    row.append(copy, toggle)
    return row
  }

  #createPreferenceIcon(name: string): HTMLElement {
    const container = document.createElement('span')
    container.className = 'settings-preference-icon'
    const icon = document.createElement('md-icon')
    icon.textContent = name
    icon.setAttribute('aria-hidden', 'true')
    container.appendChild(icon)
    return container
  }

  #createDivider(): HTMLElement {
    const divider = document.createElement('div')
    divider.className = 'settings-divider'
    divider.setAttribute('aria-hidden', 'true')
    return divider
  }

  #createSection(title: string, className: string): HTMLElement {
    const section = document.createElement('section')
    section.className = `feature-section miuix-preference-section settings-section ${className}`
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
    const labelText = translate(definition.labelKey, definition.fallback)
    button.title = labelText
    button.setAttribute('aria-label', labelText)

    const icon = document.createElement('md-icon')
    icon.className = 'appearance-mode-icon'
    icon.textContent = definition.icon
    icon.setAttribute('aria-hidden', 'true')
    const label = document.createElement('span')
    label.className = 'appearance-mode-label'
    label.textContent = labelText
    const check = document.createElement('md-icon')
    check.className = 'appearance-selected-icon'
    check.textContent = 'check'
    check.setAttribute('aria-hidden', 'true')
    button.append(icon, label, check)
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
      this.#element
        ?.querySelector<HTMLElement>(`[data-mode="${values[nextIndex!]}"]`)
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

    const effectiveAccent = this.appearance.accent
    const colorTrigger = this.#element?.querySelector<HTMLElement>(
      '.appearance-color-trigger',
    )
    const definition = ACCENTS.find(item => item.value === effectiveAccent)
    if (colorTrigger) {
      const label = definition
        ? translate(definition.labelKey, definition.fallback)
        : effectiveAccent
      colorTrigger.querySelector<HTMLElement>('.settings-language-current')!.textContent = label
      colorTrigger.setAttribute(
        'aria-label',
        `${translate('settings_color', 'Accent color')}: ${label}`,
      )
    }
    this.#element?.querySelectorAll<MdMenuItem>('.appearance-color-option').forEach(item => {
      const selected = item.dataset.accent === effectiveAccent
      item.selected = selected
      item.classList.toggle('current', selected)
      item.setAttribute('aria-selected', String(selected))
    })

    const colorRow = this.#element?.querySelector<HTMLElement>('.settings-color-row')
    const showAccent = this.appearance.getOption('monet')
    colorRow?.classList.toggle('collapsed', !showAccent)
    if (showAccent) colorRow?.removeAttribute('aria-hidden')
    else {
      colorRow?.setAttribute('aria-hidden', 'true')
      const colorMenu = colorRow?.querySelector<MdMenu>('.appearance-color-menu')
      if (colorMenu) colorMenu.open = false
    }

    this.#element?.querySelectorAll<SwitchElement>('[data-appearance-option]').forEach(toggle => {
      const option = toggle.dataset.appearanceOption as AppearanceOption | undefined
      if (option === undefined) return
      const enabled = this.appearance.getOption(option)
      toggle.selected = enabled
      toggle.closest<HTMLElement>('.settings-toggle-row')
        ?.classList.toggle('enabled', enabled)
    })
  }
}

interface Translations {
  [key: string]: string
}

export class I18nManager {
  static readonly #RTL_LANGUAGES: ReadonlySet<string> = new Set([
    'ar', 'fa', 'he', 'ur', 'ps', 'sd', 'ku', 'yi', 'dv',
  ])

  #currentLang = 'en'
  #preference = 'default'
  #translations: Translations = {}
  #baseTranslations: Translations = {}
  #availableLanguages: string[] = ['en']
  #languages: Record<string, string> = {}

  get lang(): string {
    return this.#currentLang
  }

  get preference(): string {
    return this.#preference
  }

  get languages(): Record<string, string> {
    return this.#languages
  }

  t(id: string, ...args: unknown[]): string {
    const translation = this.#translations[id] ?? this.#baseTranslations[id] ?? id
    if (args.length === 0) return translation

    let argIndex = 0
    return translation.replace(/%(?:(\d+)\$)?([%sdfx])/g, (match, index: string | undefined, type: string) => {
      if (type === '%') return '%'
      if (index !== undefined) {
        const indexedArg = Number.parseInt(index, 10) - 1
        return indexedArg < args.length ? String(args[indexedArg]) : match
      }
      const arg = args[argIndex++]
      return arg !== undefined ? String(arg) : match
    })
  }

  async init(): Promise<void> {
    try {
      this.#baseTranslations = await this.#fetchTranslations('./locales/strings/en.xml')
      this.#currentLang = await this.#detectLanguage()

      if (this.#currentLang !== 'en') {
        const selectedTranslations = await this.#fetchTranslations(
          `./locales/strings/${this.#currentLang}.xml`,
        )
        this.#translations = { ...this.#baseTranslations, ...selectedTranslations }
      } else {
        this.#translations = this.#baseTranslations
      }
    } catch (error) {
      console.error('Error loading translations:', error)
      this.#currentLang = 'en'
      this.#translations = this.#baseTranslations
    }
    this.#applyDirection()
  }

  setLanguage(lang: string): void {
    const url = new URL(window.location.href)
    if (lang !== 'default' && this.#availableLanguages.includes(lang)) {
      url.searchParams.set('lang', lang)
    } else {
      url.searchParams.delete('lang')
    }
    window.location.replace(url.href)
  }

  async #fetchTranslations(path: string): Promise<Translations> {
    const response = await fetch(path)
    if (!response.ok) throw new Error(`Unable to load ${path}`)
    return this.#parseXml(await response.text())
  }

  #parseXml(xmlText: string): Translations {
    const document = new DOMParser().parseFromString(xmlText, 'text/xml')
    if (document.querySelector('parsererror')) throw new Error('Invalid translation XML')

    const result: Translations = {}
    document.querySelectorAll('string[name]').forEach(element => {
      const name = element.getAttribute('name')
      if (name !== null) result[name] = (element.textContent ?? '').replace(/\\n/g, '\n')
    })
    return result
  }

  async #detectLanguage(): Promise<string> {
    try {
      const response = await fetch('./locales/languages.json')
      if (!response.ok) throw new Error('Unable to load the language list')
      this.#languages = await response.json() as Record<string, string>
      this.#availableLanguages = Object.keys(this.#languages)

      const requested = new URL(window.location.href).searchParams.get('lang')
      if (requested !== null && this.#availableLanguages.includes(requested)) {
        this.#preference = requested
        return requested
      }

      this.#preference = 'default'
      for (const locale of navigator.languages.length > 0 ? navigator.languages : [navigator.language]) {
        if (this.#availableLanguages.includes(locale)) return locale
        const baseCode = locale.split('-')[0]
        if (this.#availableLanguages.includes(baseCode)) return baseCode
      }
      return 'en'
    } catch (error) {
      console.error('Error detecting user language:', error)
      return 'en'
    }
  }

  #applyDirection(): void {
    const baseCode = this.#currentLang.split('-')[0]
    document.documentElement.setAttribute(
      'dir',
      I18nManager.#RTL_LANGUAGES.has(baseCode) ? 'rtl' : 'ltr',
    )
  }
}

export const i18n = new I18nManager()

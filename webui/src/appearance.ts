export const APPEARANCE_MODES = ['dark', 'amoled', 'light', 'auto'] as const
export type AppearanceMode = typeof APPEARANCE_MODES[number]

export const ACCENT_COLORS = [
  'blue',
  'yellow',
  'red',
  'purple',
  'green',
  'orange',
  'pink',
  'cyan',
  'grey',
  'system',
] as const
export type AccentColor = typeof ACCENT_COLORS[number]

type ResolvedMode = 'light' | 'dark'
type AppearanceListener = () => void

interface AccentPalette {
  primary: string
  onPrimary: string
  primaryContainer: string
  onPrimaryContainer: string
}

const DEFAULT_MODE: AppearanceMode = 'auto'
const DEFAULT_ACCENT: AccentColor = 'system'
const THEME_QUERY = 'theme'
const ACCENT_QUERY = 'accent'
const APPEARANCE_STORAGE_KEY = 'omk-appearance'
const ACCENT_PROPERTIES = [
  '--md-sys-color-primary',
  '--md-sys-color-on-primary',
  '--md-sys-color-primary-container',
  '--md-sys-color-on-primary-container',
  '--md-sys-color-secondary',
  '--md-sys-color-on-secondary',
  '--md-sys-color-secondary-container',
  '--md-sys-color-on-secondary-container',
  '--md-sys-color-inverse-primary',
] as const

const ACCENTS: Record<Exclude<AccentColor, 'system'>, Record<ResolvedMode, AccentPalette>> = {
  blue: {
    light: {
      primary: '#1157ce',
      onPrimary: '#ffffff',
      primaryContainer: '#d9e2ff',
      onPrimaryContainer: '#001a42',
    },
    dark: {
      primary: '#adc6ff',
      onPrimary: '#002e69',
      primaryContainer: '#004494',
      onPrimaryContainer: '#d9e2ff',
    },
  },
  yellow: {
    light: {
      primary: '#8f4e06',
      onPrimary: '#ffffff',
      primaryContainer: '#ffdcc1',
      onPrimaryContainer: '#301400',
    },
    dark: {
      primary: '#ffb86c',
      onPrimary: '#4e2600',
      primaryContainer: '#713700',
      onPrimaryContainer: '#ffdcc1',
    },
  },
  red: {
    light: {
      primary: '#b3251e',
      onPrimary: '#ffffff',
      primaryContainer: '#ffdad6',
      onPrimaryContainer: '#410002',
    },
    dark: {
      primary: '#ffb4ab',
      onPrimary: '#690005',
      primaryContainer: '#93000a',
      onPrimaryContainer: '#ffdad6',
    },
  },
  purple: {
    light: {
      primary: '#6750a4',
      onPrimary: '#ffffff',
      primaryContainer: '#eaddff',
      onPrimaryContainer: '#21005d',
    },
    dark: {
      primary: '#d0bcff',
      onPrimary: '#381e72',
      primaryContainer: '#4f378b',
      onPrimaryContainer: '#eaddff',
    },
  },
  green: {
    light: {
      primary: '#006c35',
      onPrimary: '#ffffff',
      primaryContainer: '#8ff7ad',
      onPrimaryContainer: '#00210d',
    },
    dark: {
      primary: '#72dc91',
      onPrimary: '#00391a',
      primaryContainer: '#005228',
      onPrimaryContainer: '#8ff7ad',
    },
  },
  orange: {
    light: {
      primary: '#9a4600',
      onPrimary: '#ffffff',
      primaryContainer: '#ffdbca',
      onPrimaryContainer: '#341100',
    },
    dark: {
      primary: '#ffb68d',
      onPrimary: '#552100',
      primaryContainer: '#793000',
      onPrimaryContainer: '#ffdbca',
    },
  },
  pink: {
    light: {
      primary: '#b60d6e',
      onPrimary: '#ffffff',
      primaryContainer: '#ffd8e9',
      onPrimaryContainer: '#3e0022',
    },
    dark: {
      primary: '#ffafd2',
      onPrimary: '#650037',
      primaryContainer: '#8e0050',
      onPrimaryContainer: '#ffd8e9',
    },
  },
  cyan: {
    light: {
      primary: '#00687c',
      onPrimary: '#ffffff',
      primaryContainer: '#adedff',
      onPrimaryContainer: '#001f27',
    },
    dark: {
      primary: '#55d6f2',
      onPrimary: '#003640',
      primaryContainer: '#004e5e',
      onPrimaryContainer: '#adedff',
    },
  },
  grey: {
    light: {
      primary: '#5e5e5e',
      onPrimary: '#ffffff',
      primaryContainer: '#e2e2e2',
      onPrimaryContainer: '#1b1b1b',
    },
    dark: {
      primary: '#c6c6c6',
      onPrimary: '#303030',
      primaryContainer: '#464646',
      onPrimaryContainer: '#e2e2e2',
    },
  },
}

function isAppearanceMode(value: string | null): value is AppearanceMode {
  return value !== null && APPEARANCE_MODES.some(mode => mode === value)
}

function isAccentColor(value: string | null): value is AccentColor {
  return value !== null && ACCENT_COLORS.some(color => color === value)
}

export class AppearanceController {
  #mode: AppearanceMode
  #accent: AccentColor
  #systemTheme = window.matchMedia('(prefers-color-scheme: dark)')
  #listeners: AppearanceListener[] = []

  constructor() {
    const url = new URL(window.location.href)
    const stored = AppearanceController.#readStoredAppearance()
    const requestedMode = url.searchParams.get(THEME_QUERY) ?? stored.mode
    const requestedAccent = url.searchParams.get(ACCENT_QUERY) ?? stored.accent
    this.#mode = isAppearanceMode(requestedMode) ? requestedMode : DEFAULT_MODE
    this.#accent = isAccentColor(requestedAccent) ? requestedAccent : DEFAULT_ACCENT
    this.#systemTheme.addEventListener('change', () => {
      if (this.#mode !== 'auto') return
      this.#apply()
      this.#emit()
    })
    this.#apply()
  }

  get mode(): AppearanceMode {
    return this.#mode
  }

  get accent(): AccentColor {
    return this.#accent
  }

  setMode(mode: AppearanceMode): void {
    if (mode === this.#mode) return
    this.#mode = mode
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
  }

  setAccent(accent: AccentColor): void {
    if (accent === this.#accent) return
    this.#accent = accent
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
  }

  onChange(listener: AppearanceListener): void {
    this.#listeners.push(listener)
  }

  static #readStoredAppearance(): { mode: string | null, accent: string | null } {
    try {
      const value = window.localStorage.getItem(APPEARANCE_STORAGE_KEY)
      if (value === null) return { mode: null, accent: null }
      const parsed: unknown = JSON.parse(value)
      if (typeof parsed !== 'object' || parsed === null) return { mode: null, accent: null }
      const record = parsed as Record<string, unknown>
      return {
        mode: typeof record.mode === 'string' ? record.mode : null,
        accent: typeof record.accent === 'string' ? record.accent : null,
      }
    } catch {
      return { mode: null, accent: null }
    }
  }

  #storeAppearance(): void {
    try {
      window.localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify({
        mode: this.#mode,
        accent: this.#accent,
      }))
    } catch {
      // Some WebViews can disable storage; the in-memory setting still applies.
    }
  }

  #resolvedMode(): ResolvedMode {
    if (this.#mode === 'light') return 'light'
    if (this.#mode === 'auto') return this.#systemTheme.matches ? 'dark' : 'light'
    return 'dark'
  }

  #syncUrl(): void {
    const url = new URL(window.location.href)
    if (this.#mode === DEFAULT_MODE) url.searchParams.delete(THEME_QUERY)
    else url.searchParams.set(THEME_QUERY, this.#mode)
    if (this.#accent === DEFAULT_ACCENT) url.searchParams.delete(ACCENT_QUERY)
    else url.searchParams.set(ACCENT_QUERY, this.#accent)
    window.history.replaceState(window.history.state, '', url.href)
  }

  #apply(): void {
    const root = document.documentElement
    const resolved = this.#resolvedMode()
    root.dataset.themeMode = this.#mode
    root.dataset.themeResolved = resolved
    root.dataset.themeAccent = this.#accent
    root.style.colorScheme = resolved

    for (const property of ACCENT_PROPERTIES) root.style.removeProperty(property)
    if (this.#accent === 'system') return

    const palette = ACCENTS[this.#accent][resolved]
    const values: Record<(typeof ACCENT_PROPERTIES)[number], string> = {
      '--md-sys-color-primary': palette.primary,
      '--md-sys-color-on-primary': palette.onPrimary,
      '--md-sys-color-primary-container': palette.primaryContainer,
      '--md-sys-color-on-primary-container': palette.onPrimaryContainer,
      '--md-sys-color-secondary': palette.primary,
      '--md-sys-color-on-secondary': palette.onPrimary,
      '--md-sys-color-secondary-container': palette.primaryContainer,
      '--md-sys-color-on-secondary-container': palette.onPrimaryContainer,
      '--md-sys-color-inverse-primary': palette.primary,
    }
    for (const [property, value] of Object.entries(values)) root.style.setProperty(property, value)
  }

  #emit(): void {
    for (const listener of this.#listeners) listener()
  }
}

export const appearance = new AppearanceController()

import { setThemeMode } from 'miuix-vue'

export const APPEARANCE_MODES = ['auto', 'light', 'dark', 'amoled'] as const
export type AppearanceMode = typeof APPEARANCE_MODES[number]

export const ACCENT_COLORS = [
  'default',
  'red',
  'pink',
  'purple',
  'deepPurple',
  'indigo',
  'blue',
  'cyan',
  'teal',
  'green',
  'yellow',
  'amber',
  'orange',
  'brown',
  'blueGrey',
  'sakura',
] as const
export type AccentColor = typeof ACCENT_COLORS[number]

export const APPEARANCE_OPTIONS = [
  'monet',
  'barBlur',
  'floatingBottomBar',
  'liquidGlass',
] as const
export type AppearanceOption = typeof APPEARANCE_OPTIONS[number]

type ResolvedMode = 'light' | 'dark'
type AppearanceListener = () => void

interface AccentPalette {
  primary: string
  onPrimary: string
  primaryContainer: string
  onPrimaryContainer: string
}

const DEFAULT_MODE: AppearanceMode = 'auto'
type ManualAccent = Exclude<AccentColor, 'default'>
const DEFAULT_ACCENT = 'default' as const satisfies AccentColor
const DEFAULT_MANUAL_ACCENT: ManualAccent = 'blue'
const DEFAULT_OPTIONS: Readonly<Record<AppearanceOption, boolean>> = {
  monet: true,
  barBlur: false,
  floatingBottomBar: false,
  liquidGlass: false,
}
const THEME_QUERY = 'theme'
const ACCENT_QUERY = 'accent'
const APPEARANCE_STORAGE_KEY = 'omk-appearance'
const ACCENT_PROPERTIES = [
  '--miuix-primary',
  '--miuix-primary-container',
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

const ACCENTS: Record<ManualAccent, Record<ResolvedMode, AccentPalette>> = {
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
  deepPurple: {
    light: {
      primary: '#5f3da8',
      onPrimary: '#ffffff',
      primaryContainer: '#e9ddff',
      onPrimaryContainer: '#1e0b4f',
    },
    dark: {
      primary: '#d0bcff',
      onPrimary: '#362065',
      primaryContainer: '#4d3780',
      onPrimaryContainer: '#e9ddff',
    },
  },
  indigo: {
    light: {
      primary: '#4355b9',
      onPrimary: '#ffffff',
      primaryContainer: '#dce2ff',
      onPrimaryContainer: '#10174b',
    },
    dark: {
      primary: '#bec6ff',
      onPrimary: '#27337e',
      primaryContainer: '#3d4a95',
      onPrimaryContainer: '#dce2ff',
    },
  },
  teal: {
    light: {
      primary: '#006a60',
      onPrimary: '#ffffff',
      primaryContainer: '#9ef2e5',
      onPrimaryContainer: '#00201c',
    },
    dark: {
      primary: '#80dbcf',
      onPrimary: '#003731',
      primaryContainer: '#005047',
      onPrimaryContainer: '#9ef2e5',
    },
  },
  amber: {
    light: {
      primary: '#8b5000',
      onPrimary: '#ffffff',
      primaryContainer: '#ffddb4',
      onPrimaryContainer: '#2d1600',
    },
    dark: {
      primary: '#ffb95f',
      onPrimary: '#4d2600',
      primaryContainer: '#6d3900',
      onPrimaryContainer: '#ffddb4',
    },
  },
  brown: {
    light: {
      primary: '#815343',
      onPrimary: '#ffffff',
      primaryContainer: '#ffdbce',
      onPrimaryContainer: '#32130a',
    },
    dark: {
      primary: '#ffb59f',
      onPrimary: '#4c251a',
      primaryContainer: '#653b2e',
      onPrimaryContainer: '#ffdbce',
    },
  },
  blueGrey: {
    light: {
      primary: '#4f616d',
      onPrimary: '#ffffff',
      primaryContainer: '#d3e5ef',
      onPrimaryContainer: '#091e28',
    },
    dark: {
      primary: '#b7cad4',
      onPrimary: '#21333b',
      primaryContainer: '#394b53',
      onPrimaryContainer: '#d3e5ef',
    },
  },
  sakura: {
    light: {
      primary: '#a23f54',
      onPrimary: '#ffffff',
      primaryContainer: '#ffd9df',
      onPrimaryContainer: '#3f0717',
    },
    dark: {
      primary: '#ffb2bd',
      onPrimary: '#610f25',
      primaryContainer: '#7f293d',
      onPrimaryContainer: '#ffd9df',
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
}

function isAppearanceMode(value: string | null): value is AppearanceMode {
  return value !== null && APPEARANCE_MODES.some(mode => mode === value)
}

function normalizeAccent(value: string | null): AccentColor | null {
  if (value === 'system') return DEFAULT_ACCENT
  if (value === 'grey') return 'blueGrey'
  return ACCENT_COLORS.find(color => color === value) ?? null
}

export class AppearanceController {
  #mode: AppearanceMode
  #accent: AccentColor
  #options: Record<AppearanceOption, boolean>
  #systemTheme = window.matchMedia('(prefers-color-scheme: dark)')
  #listeners: AppearanceListener[] = []

  constructor() {
    const url = new URL(window.location.href)
    const stored = AppearanceController.#readStoredAppearance()
    const requestedMode = url.searchParams.get(THEME_QUERY) ?? stored.mode
    const queryAccent = url.searchParams.get(ACCENT_QUERY)
    const requestedAccent = normalizeAccent(queryAccent ?? stored.accent)
    this.#mode = isAppearanceMode(requestedMode) ? requestedMode : DEFAULT_MODE
    this.#accent = requestedAccent ?? DEFAULT_ACCENT
    this.#options = { ...DEFAULT_OPTIONS, ...stored.options }
    if (stored.options.monet === undefined && normalizeAccent(stored.accent) !== null) {
      this.#options.monet = stored.accent === DEFAULT_ACCENT || stored.accent === 'system'
    }
    if (this.#options.liquidGlass) this.#options.floatingBottomBar = true
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

  getOption(option: AppearanceOption): boolean {
    return this.#options[option]
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
    const normalized = normalizeAccent(accent)
    if (normalized === null || normalized === this.#accent) return
    this.#accent = normalized
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
  }

  setOption(option: AppearanceOption, enabled: boolean): void {
    const floatingChanged = option === 'liquidGlass' && enabled
      && !this.#options.floatingBottomBar
    const glassChanged = option === 'floatingBottomBar' && !enabled
      && this.#options.liquidGlass
    if (this.#options[option] === enabled && !floatingChanged && !glassChanged) return
    this.#options[option] = enabled
    if (floatingChanged) this.#options.floatingBottomBar = true
    if (glassChanged) this.#options.liquidGlass = false
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
  }

  onChange(listener: AppearanceListener): () => void {
    this.#listeners.push(listener)
    return () => {
      const index = this.#listeners.indexOf(listener)
      if (index !== -1) this.#listeners.splice(index, 1)
    }
  }

  static #readStoredAppearance(): {
    mode: string | null
    accent: string | null
    options: Partial<Record<AppearanceOption, boolean>>
  } {
    try {
      const value = window.localStorage.getItem(APPEARANCE_STORAGE_KEY)
      if (value === null) return { mode: null, accent: null, options: {} }
      const parsed: unknown = JSON.parse(value)
      if (typeof parsed !== 'object' || parsed === null) {
        return { mode: null, accent: null, options: {} }
      }
      const record = parsed as Record<string, unknown>
      const options: Partial<Record<AppearanceOption, boolean>> = {}
      for (const option of APPEARANCE_OPTIONS) {
        if (typeof record[option] === 'boolean') options[option] = record[option]
      }
      return {
        mode: typeof record.mode === 'string' ? record.mode : null,
        accent: typeof record.accent === 'string' ? record.accent : null,
        options,
      }
    } catch {
      return { mode: null, accent: null, options: {} }
    }
  }

  #storeAppearance(): void {
    try {
      window.localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify({
        mode: this.#mode,
        accent: this.#accent,
        ...this.#options,
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
    // Keep the component library's own theme class in sync with the persisted
    // controller state.  `amoled` intentionally uses the dark Miuix palette;
    // the pure-black surface is supplied by our tokens below.
    setThemeMode(this.#mode === 'auto' ? 'system' : resolved)
    root.dataset.themeMode = this.#mode
    root.dataset.themeResolved = resolved
    root.dataset.themeAccent = this.#accent
    root.dataset.monet = String(this.#options.monet)
    root.dataset.barBlur = String(this.#options.barBlur)
    root.dataset.floatingBottomBar = String(this.#options.floatingBottomBar)
    root.dataset.liquidGlass = String(this.#options.liquidGlass)
    root.style.colorScheme = resolved

    for (const property of ACCENT_PROPERTIES) root.style.removeProperty(property)
    if (this.#options.monet && this.#accent === DEFAULT_ACCENT) {
      const fallback = ACCENTS.blue[resolved]
      const values: Record<(typeof ACCENT_PROPERTIES)[number], string> = {
        '--miuix-primary': `var(--primary, ${fallback.primary})`,
        '--miuix-primary-container': `var(--primaryContainer, ${fallback.primaryContainer})`,
        '--md-sys-color-primary': `var(--primary, ${fallback.primary})`,
        '--md-sys-color-on-primary': `var(--onPrimary, ${fallback.onPrimary})`,
        '--md-sys-color-primary-container': `var(--primaryContainer, ${fallback.primaryContainer})`,
        '--md-sys-color-on-primary-container': `var(--onPrimaryContainer, ${fallback.onPrimaryContainer})`,
        '--md-sys-color-secondary': `var(--secondary, ${fallback.primary})`,
        '--md-sys-color-on-secondary': `var(--onSecondary, ${fallback.onPrimary})`,
        '--md-sys-color-secondary-container': `var(--secondaryContainer, ${fallback.primaryContainer})`,
        '--md-sys-color-on-secondary-container': `var(--onSecondaryContainer, ${fallback.onPrimaryContainer})`,
        '--md-sys-color-inverse-primary': `var(--inversePrimary, ${fallback.primary})`,
      }
      for (const [property, value] of Object.entries(values)) root.style.setProperty(property, value)
      return
    }
    // A manually selected accent is a Monet seed and only applies while
    // dynamic Monet colors are enabled.  Disabling Monet must restore the
    // default static palette instead of leaving the previously selected
    // custom color active.
    const selectedAccent: ManualAccent = this.#options.monet && this.#accent !== DEFAULT_ACCENT
      ? this.#accent
      : DEFAULT_MANUAL_ACCENT
    const palette = ACCENTS[selectedAccent][resolved]
    const values: Record<(typeof ACCENT_PROPERTIES)[number], string> = {
      '--miuix-primary': palette.primary,
      '--miuix-primary-container': palette.primaryContainer,
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

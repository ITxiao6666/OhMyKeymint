import { setThemeMode } from 'miuix-vue'
import { exec, isKsuWebui } from 'kernelsu-alt'
import { DynamicScheme, Hct, Variant, argbFromHex, hexFromArgb } from '@material/material-color-utilities'

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

// Keep the same palette families and color specification names exposed by
// KernelSU.  The values are persisted so switching pages or reopening the
// WebUI does not reset the selected palette.
export const PALETTE_STYLES = [
  'TonalSpot',
  'Neutral',
  'Vibrant',
  'Expressive',
  'Rainbow',
  'FruitSalad',
] as const
export type PaletteStyle = typeof PALETTE_STYLES[number]
export const COLOR_SPECS = ['SPEC_2025', 'SPEC_2021'] as const
export type ColorSpec = typeof COLOR_SPECS[number]

type ResolvedMode = 'light' | 'dark'
type AppearanceListener = () => void

const DEFAULT_MODE: AppearanceMode = 'auto'
type ManualAccent = Exclude<AccentColor, 'default'>
const DEFAULT_ACCENT = 'default' as const satisfies AccentColor
const DEFAULT_PALETTE_STYLE: PaletteStyle = 'TonalSpot'
const DEFAULT_COLOR_SPEC: ColorSpec = 'SPEC_2025'
const DEFAULT_OPTIONS: Readonly<Record<AppearanceOption, boolean>> = {
  monet: true,
  barBlur: false,
  floatingBottomBar: false,
  liquidGlass: false,
}
const THEME_QUERY = 'theme'
const ACCENT_QUERY = 'accent'
const APPEARANCE_STORAGE_KEY = 'omk-appearance'
// The same seed colors exposed by KernelSU's accent picker.
export const ACCENT_SEEDS: Readonly<Record<ManualAccent, string>> = {
  red: '#f44336', pink: '#e91e63', purple: '#9c27b0', deepPurple: '#673ab7',
  indigo: '#3f51b5', blue: '#2196f3', cyan: '#00bcd4', teal: '#009688',
  green: '#4faf50', yellow: '#ffeb3b', amber: '#ffc107', orange: '#ff9800',
  brown: '#795548', blueGrey: '#607d8f', sakura: '#ff9ca8',
}
const PALETTE_VARIANTS: Record<PaletteStyle, Variant> = {
  TonalSpot: Variant.TONAL_SPOT, Neutral: Variant.NEUTRAL,
  Vibrant: Variant.VIBRANT, Expressive: Variant.EXPRESSIVE,
  Rainbow: Variant.RAINBOW, FruitSalad: Variant.FRUIT_SALAD,
}

// Read the resolved resources, including the current user's wallpaper overlays.
// Android 14+ exposes named roles; Android 12-13 exposes the tonal palette.
// No wallpaper files, settings writes, or persistent probe files are needed.
const SYSTEM_COLORS_COMMAND = `
omk_color_user="$(am get-current-user 2>/dev/null)"
case "$omk_color_user" in ''|*[!0-9]*) exit 1 ;; esac
for omk_color_mode in light dark; do
  case "$omk_color_mode" in light) omk_color_tone=600 ;; dark) omk_color_tone=200 ;; esac
  omk_color_value="$(/system/bin/cmd overlay lookup --user "$omk_color_user" android android:color/system_primary_"$omk_color_mode" 2>/dev/null)" ||
    omk_color_value="$(/system/bin/cmd overlay lookup --user "$omk_color_user" android android:color/system_accent1_"$omk_color_tone" 2>/dev/null)"
  printf '%s=%s\\n' "$omk_color_mode" "$omk_color_value"
done
`

function parseSystemColors(output: string): Partial<Record<ResolvedMode, string>> {
  const result: Partial<Record<ResolvedMode, string>> = {}
  for (const line of output.split(/\r?\n/)) {
    const mode = line.startsWith('light=') ? 'light' : line.startsWith('dark=') ? 'dark' : null
    if (!mode) continue
    const values = [...line.matchAll(/#([0-9a-f]{8}|[0-9a-f]{6})(?![0-9a-f])/gi)]
    const value = values.at(-1)?.[1]
    // Android prints AARRGGBB. System theme resources must be opaque.
    if (value && (value.length === 6 || value.slice(0, 2).toLowerCase() === 'ff')) {
      result[mode] = '#' + value.slice(-6).toLowerCase()
    }
  }
  return result
}

function supportsBackdropBlur(): boolean {
  if (typeof CSS === 'undefined' || typeof CSS.supports !== 'function') return false
  return CSS.supports('backdrop-filter', 'blur(1px)')
    || CSS.supports('-webkit-backdrop-filter', 'blur(1px)')
}

// Adapted from MIUIX MonetMapping.kt (Apache-2.0). MIUIX secondary is an
// inactive control fill (outlineVariant), not the Material secondary accent.
function monetTokens(seed: string, dark: boolean, style: PaletteStyle, spec: ColorSpec): Record<string, string> {
  const scheme = new DynamicScheme({
    sourceColorHct: Hct.fromInt(argbFromHex(seed)),
    variant: PALETTE_VARIANTS[style],
    isDark: dark,
    contrastLevel: 0,
    platform: 'phone',
    specVersion: spec === 'SPEC_2025' ? '2025' : '2021',
  })
  const mix = (foreground: number, alpha: number, background: number): string => {
    const channel = (shift: number) => Math.round(
      ((foreground >>> shift) & 255) * alpha + ((background >>> shift) & 255) * (1 - alpha),
    )
    return hexFromArgb((255 << 24) | (channel(16) << 16) | (channel(8) << 8) | channel(0))
  }
  const surface = scheme.surface
  const disabledPrimary = mix(scheme.primary, 0.38, surface)
  const disabledSecondary = mix(scheme.outlineVariant, 0.5, surface)
  const disabledSecondaryVariant = mix(scheme.surfaceContainerHigh, 0.6, surface)
  const roles: Record<string, number | string> = {
    primary: scheme.primary, 'on-primary': scheme.onPrimary,
    'primary-variant': scheme.primaryFixed, 'on-primary-variant': scheme.onPrimaryFixed,
    error: scheme.error, 'on-error': scheme.onError,
    'error-container': scheme.errorContainer, 'on-error-container': scheme.onErrorContainer,
    'primary-container': scheme.primaryContainer, 'on-primary-container': scheme.onPrimaryContainer,
    'disabled-primary': disabledPrimary,
    'disabled-on-primary': mix(scheme.onPrimary, 0.38, argbFromHex(disabledPrimary)),
    'disabled-primary-button': disabledPrimary,
    'disabled-on-primary-button': mix(scheme.onPrimary, 0.6, argbFromHex(disabledPrimary)),
    'disabled-primary-slider': disabledPrimary,
    secondary: scheme.outlineVariant, 'on-secondary': scheme.outline,
    'secondary-variant': scheme.surfaceContainerHigh, 'on-secondary-variant': scheme.onSurface,
    'disabled-secondary': disabledSecondary,
    'disabled-on-secondary': mix(scheme.onSurface, 0.38, argbFromHex(disabledSecondary)),
    'disabled-secondary-variant': disabledSecondaryVariant,
    'disabled-on-secondary-variant': mix(scheme.onSurface, 0.38, argbFromHex(disabledSecondaryVariant)),
    'secondary-container': scheme.secondaryContainer, 'on-secondary-container': scheme.onSecondaryContainer,
    'secondary-container-variant': scheme.surfaceContainerHighest,
    'on-secondary-container-variant': scheme.onSurfaceVariant,
    'tertiary-container': scheme.tertiaryContainer, 'on-tertiary-container': scheme.onTertiaryContainer,
    'tertiary-container-variant': scheme.onTertiaryContainer,
    background: scheme.background, 'on-background': scheme.onBackground,
    'on-background-variant': scheme.primary,
    surface, 'on-surface': scheme.onSurface, 'surface-variant': scheme.surfaceVariant,
    'on-surface-secondary': mix(scheme.onSurface, 0.8, surface),
    'on-surface-variant-summary': scheme.onSurfaceVariant,
    'on-surface-variant-actions': scheme.onSurfaceVariant,
    'disabled-on-surface': scheme.onSurface,
    'surface-container': scheme.surfaceContainer, 'on-surface-container': scheme.onSurface,
    'on-surface-container-variant': scheme.onSurfaceVariant,
    'surface-container-high': scheme.surfaceContainerHigh,
    'on-surface-container-high': mix(scheme.onSurface, 0.8, scheme.surfaceContainerHigh),
    'surface-container-highest': scheme.surfaceContainerHighest,
    'on-surface-container-highest': scheme.onSurface,
    outline: scheme.outline, 'divider-line': scheme.outlineVariant,
    'window-dimming': dark ? 'rgb(0 0 0 / 60%)' : 'rgb(0 0 0 / 30%)',
    'slider-key-point': scheme.primary, 'slider-key-point-foreground': scheme.surfaceContainerHigh,
    'slider-background': mix(scheme.primary, 0.2, surface),
  }
  return Object.fromEntries(Object.entries(roles).map(([role, color]) => [
    '--m-color-' + role, typeof color === 'number' ? hexFromArgb(color) : color,
  ]))
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
  #paletteStyle: PaletteStyle
  #colorSpec: ColorSpec
  #interfaceScale = 100
  #systemTheme = window.matchMedia('(prefers-color-scheme: dark)')
  #listeners: AppearanceListener[] = []
  #systemColors: Partial<Record<ResolvedMode, string>> = {}
  #colorRefresh: Promise<void> | null = null
  #lastColorRefresh = 0
  #paletteKey = ''
  #palette: Record<string, string> = {}
  #appliedTokens: Record<string, string> = {}

  constructor() {
    const url = new URL(window.location.href)
    const stored = AppearanceController.#readStoredAppearance()
    const requestedMode = url.searchParams.get(THEME_QUERY) ?? stored.mode
    const queryAccent = url.searchParams.get(ACCENT_QUERY)
    const requestedAccent = normalizeAccent(queryAccent ?? stored.accent)
    this.#mode = isAppearanceMode(requestedMode) ? requestedMode : DEFAULT_MODE
    this.#accent = requestedAccent ?? DEFAULT_ACCENT
    this.#options = { ...DEFAULT_OPTIONS, ...stored.options }
    this.#paletteStyle = PALETTE_STYLES.includes(stored.paletteStyle as PaletteStyle)
      ? stored.paletteStyle as PaletteStyle : DEFAULT_PALETTE_STYLE
    this.#colorSpec = COLOR_SPECS.includes(stored.colorSpec as ColorSpec)
      ? stored.colorSpec as ColorSpec : DEFAULT_COLOR_SPEC
    this.#interfaceScale = typeof stored.interfaceScale === 'number'
      ? Math.max(80, Math.min(110, Math.round(stored.interfaceScale))) : 100
    if (stored.options.monet === undefined && normalizeAccent(stored.accent) !== null) {
      this.#options.monet = stored.accent === DEFAULT_ACCENT || stored.accent === 'system'
    }
    this.#systemTheme.addEventListener('change', () => {
      this.#apply()
      this.#emit()
      void this.refreshSystemColors()
    })
    window.addEventListener('focus', () => { void this.refreshSystemColors() })
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') void this.refreshSystemColors()
    })
    this.#apply()
    void this.refreshSystemColors()
  }

  async refreshSystemColors(): Promise<void> {
    if (!isKsuWebui()) return
    if (this.#colorRefresh) return this.#colorRefresh
    if (Date.now() - this.#lastColorRefresh < 1000) return
    this.#lastColorRefresh = Date.now()
    this.#colorRefresh = (async () => {
      const hostBars = this.#refreshHostBarColor()
      try {
        if (!this.#options.monet || this.#accent !== DEFAULT_ACCENT) return
        const result = await exec(SYSTEM_COLORS_COMMAND)
        if (result.errno !== 0) return
        const colors = parseSystemColors(result.stdout)
        if (!colors.light && !colors.dark) return
        const nextColors = { ...this.#systemColors, ...colors }
        if (nextColors.light === this.#systemColors.light && nextColors.dark === this.#systemColors.dark) return
        this.#systemColors = nextColors
        this.#apply()
        this.#emit()
      } catch (error) {
        console.warn('Unable to read Android dynamic colors:', error)
      } finally {
        await hostBars
      }
    })()
    try {
      await this.#colorRefresh
    } finally {
      this.#colorRefresh = null
    }
  }

  async #refreshHostBarColor(): Promise<void> {
    // KernelSU owns the native bar icons and exports its active surface here.
    // Use its surface only when the host and WebUI light/dark modes differ.
    // Matching modes can extend the WebUI surface into the safe areas.
    const controller = new AbortController()
    const timer = window.setTimeout(() => controller.abort(), 2000)
    let surface: string | undefined
    try {
      const response = await fetch('/internal/colors.css', {
        cache: 'no-store', signal: controller.signal,
      })
      if (response.ok) {
        const css = await response.text()
        // MonetColorsProvider uses CSS RRGGBB/RRGGBBAA, not Android AARRGGBB.
        const value = css.match(/(?:^|[;{])\s*--surface\s*:\s*(#[0-9a-f]{6}(?:ff)?)\s*;/i)?.[1]
        if (value) surface = value.slice(0, 7)
      }
    } catch {
      // Keep the CSS prefers-color-scheme fallback for unsupported hosts.
    } finally {
      window.clearTimeout(timer)
    }
    const root = document.documentElement
    if (surface) {
      root.style.setProperty('--omk-host-bar-background', surface)
      root.dataset.hostTheme = Hct.fromInt(argbFromHex(surface)).tone >= 50 ? 'light' : 'dark'
    } else {
      root.style.removeProperty('--omk-host-bar-background')
      delete root.dataset.hostTheme
    }
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

  get paletteStyle(): PaletteStyle { return this.#paletteStyle }

  get colorSpec(): ColorSpec { return this.#colorSpec }

  get interfaceScale(): number { return this.#interfaceScale }

  setInterfaceScale(scale: number): void {
    const normalized = Math.max(80, Math.min(110, Math.round(scale)))
    if (normalized === this.#interfaceScale) return
    this.#interfaceScale = normalized
    this.#storeAppearance()
    this.#apply()
    this.#emit()
  }

  setMode(mode: AppearanceMode): void {
    if (mode === this.#mode) return
    this.#mode = mode
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
    void this.refreshSystemColors()
  }

  setAccent(accent: AccentColor): void {
    const normalized = normalizeAccent(accent)
    if (normalized === null || normalized === this.#accent) return
    this.#accent = normalized
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
    void this.refreshSystemColors()
  }

  setPaletteStyle(style: PaletteStyle): void {
    if (!PALETTE_STYLES.includes(style) || style === this.#paletteStyle) return
    this.#paletteStyle = style
    this.#storeAppearance()
    this.#apply()
    this.#emit()
  }

  setColorSpec(spec: ColorSpec): void {
    if (!COLOR_SPECS.includes(spec) || spec === this.#colorSpec) return
    this.#colorSpec = spec
    this.#storeAppearance()
    this.#apply()
    this.#emit()
  }

  setOption(option: AppearanceOption, enabled: boolean): void {
    if (this.#options[option] === enabled) return
    this.#options[option] = enabled
    this.#storeAppearance()
    this.#syncUrl()
    this.#apply()
    this.#emit()
    void this.refreshSystemColors()
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
    paletteStyle: string | null
    colorSpec: string | null
    interfaceScale: number | null
    options: Partial<Record<AppearanceOption, boolean>>
  } {
    try {
      const value = window.localStorage.getItem(APPEARANCE_STORAGE_KEY)
      if (value === null) return { mode: null, accent: null, paletteStyle: null, colorSpec: null, interfaceScale: null, options: {} }
      const parsed: unknown = JSON.parse(value)
      if (typeof parsed !== 'object' || parsed === null) {
        return { mode: null, accent: null, paletteStyle: null, colorSpec: null, interfaceScale: null, options: {} }
      }
      const record = parsed as Record<string, unknown>
      const options: Partial<Record<AppearanceOption, boolean>> = {}
      for (const option of APPEARANCE_OPTIONS) {
        if (typeof record[option] === 'boolean') options[option] = record[option]
      }
      return {
        mode: typeof record.mode === 'string' ? record.mode : null,
        accent: typeof record.accent === 'string' ? record.accent : null,
        paletteStyle: typeof record.paletteStyle === 'string' ? record.paletteStyle : null,
        colorSpec: typeof record.colorSpec === 'string' ? record.colorSpec : null,
        interfaceScale: typeof record.interfaceScale === 'number' ? record.interfaceScale : null,
        options,
      }
    } catch {
      return { mode: null, accent: null, paletteStyle: null, colorSpec: null, interfaceScale: null, options: {} }
    }
  }

  #storeAppearance(): void {
    try {
      window.localStorage.setItem(APPEARANCE_STORAGE_KEY, JSON.stringify({
        mode: this.#mode,
        accent: this.#accent,
        paletteStyle: this.#paletteStyle,
        colorSpec: this.#colorSpec,
        interfaceScale: this.#interfaceScale,
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
    // KernelSU disables its RenderEffect blur when the platform cannot
    // provide it. Keep the same explicit capability state for the WebView
    // fallback instead of painting a solid bar that looks like blur.
    root.dataset.backdropBlurSupported = String(supportsBackdropBlur())
    root.dataset.paletteStyle = this.#paletteStyle
    root.dataset.colorSpec = this.#colorSpec
    root.style.setProperty('--omk-ui-scale', String(this.#interfaceScale / 100))
    root.style.colorScheme = resolved

    const seed = this.#accent === DEFAULT_ACCENT
      ? this.#systemColors[resolved] : ACCENT_SEEDS[this.#accent]
    root.dataset.monetSource = !this.#options.monet ? 'disabled'
      : this.#accent !== DEFAULT_ACCENT ? 'custom' : seed ? 'system' : 'unavailable'
    // A failed/unsupported system query keeps the static MIUIX palette rather
    // than presenting a hardcoded color as wallpaper-derived Monet.
    let tokens: Record<string, string> = {}
    if (this.#options.monet && seed) {
      root.dataset.monetSeed = seed
      const key = [seed, resolved, this.#paletteStyle, this.#colorSpec].join(':')
      if (key !== this.#paletteKey) {
        this.#palette = monetTokens(seed, resolved === 'dark', this.#paletteStyle, this.#colorSpec)
        this.#paletteKey = key
      }
      tokens = { ...this.#palette }
      if (this.#mode === 'amoled') {
        Object.assign(tokens, {
          '--m-color-background': '#000000', '--m-color-surface': '#000000',
          '--m-color-surface-variant': '#101010', '--m-color-surface-container': '#101010',
          '--m-color-surface-container-high': '#171717', '--m-color-surface-container-highest': '#202020',
        })
      }
    } else {
      delete root.dataset.monetSeed
    }
    // Unchanged preferences must not remove and recreate the entire palette.
    // Also remove overrides when Monet is disabled or its seed is unavailable.
    for (const property of Object.keys(this.#appliedTokens)) {
      if (!(property in tokens)) root.style.removeProperty(property)
    }
    for (const [property, value] of Object.entries(tokens)) {
      if (this.#appliedTokens[property] !== value) root.style.setProperty(property, value)
    }
    this.#appliedTokens = tokens
  }

  #emit(): void {
    for (const listener of this.#listeners) listener()
  }
}

export const appearance = new AppearanceController()

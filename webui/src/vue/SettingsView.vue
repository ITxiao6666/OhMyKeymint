<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import {
  MiuixCard,
  MiuixDivider,
  MiuixDropdownPreference,
  MiuixIcon,
  MiuixSmallTitle,
  MiuixSpinnerPreference,
  MiuixSwitchPreference,
  MiuixTabRow,
  MiuixTopAppBar,
  type MiuixDropdownItem,
} from 'miuix-vue'
import { Background, Layers, Sidebar, Theme, Translate, Tune } from 'miuix-vue/icons'
import {
  ACCENT_COLORS,
  APPEARANCE_MODES,
  appearance,
  type AccentColor,
  type AppearanceMode,
  type AppearanceOption,
} from '../appearance'
import { i18n } from '../i18n'

interface Choice<T extends string> {
  value: T
  labelKey: string
  fallback: string
}

const MODE_CHOICES: readonly Choice<AppearanceMode>[] = [
  { value: 'auto', labelKey: 'theme_mode_auto', fallback: 'Follow system' },
  { value: 'light', labelKey: 'theme_mode_light', fallback: 'Light' },
  { value: 'dark', labelKey: 'theme_mode_dark', fallback: 'Dark' },
  { value: 'amoled', labelKey: 'theme_mode_amoled', fallback: 'Pure black' },
]

const ACCENT_CHOICES: readonly Choice<AccentColor>[] = [
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

const ACCENT_SWATCHES: Readonly<Record<AccentColor, string>> = {
  default: 'var(--m-color-primary)',
  red: '#d93025',
  pink: '#d81b60',
  purple: '#8e24aa',
  deepPurple: '#673ab7',
  indigo: '#3f51b5',
  blue: '#1976d2',
  cyan: '#0097a7',
  teal: '#00897b',
  green: '#2e7d32',
  yellow: '#f9a825',
  amber: '#ff8f00',
  orange: '#ef6c00',
  brown: '#795548',
  blueGrey: '#546e7a',
  sakura: '#e5739a',
}

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const modeTabs = computed<string[]>(() => MODE_CHOICES.map(choice => translate(choice.labelKey, choice.fallback)))
const languageCodes = ['default', ...Object.keys(i18n.languages)]
const languageItems = computed<string[]>(() => [
  translate('settings_language_auto', 'Follow system language'),
  ...Object.values(i18n.languages),
])
const accentItems = computed<MiuixDropdownItem[]>(() => ACCENT_CHOICES.map(choice => ({
  text: translate(choice.labelKey, choice.fallback),
  color: ACCENT_SWATCHES[choice.value],
})))

const modeIndex = ref(Math.max(0, APPEARANCE_MODES.indexOf(appearance.mode)))
const languageIndex = ref(Math.max(0, languageCodes.indexOf(i18n.preference)))
const accentIndex = ref(Math.max(0, ACCENT_COLORS.indexOf(appearance.accent)))
const options = ref<Record<AppearanceOption, boolean>>(readOptions())

function readOptions(): Record<AppearanceOption, boolean> {
  return {
    monet: appearance.getOption('monet'),
    barBlur: appearance.getOption('barBlur'),
    floatingBottomBar: appearance.getOption('floatingBottomBar'),
    liquidGlass: appearance.getOption('liquidGlass'),
  }
}

function syncAppearanceState(): void {
  modeIndex.value = Math.max(0, APPEARANCE_MODES.indexOf(appearance.mode))
  accentIndex.value = Math.max(0, ACCENT_COLORS.indexOf(appearance.accent))
  options.value = readOptions()
}

function selectMode(index: number): void {
  const choice = MODE_CHOICES[index]
  if (!choice) return
  appearance.setMode(choice.value)
  syncAppearanceState()
}

function selectLanguage(index: number): void {
  const language = languageCodes[index]
  if (language === undefined) return
  languageIndex.value = index
  if (language !== i18n.preference) i18n.setLanguage(language)
}

function selectAccent(index: number): void {
  const choice = ACCENT_CHOICES[index]
  if (!choice) return
  appearance.setAccent(choice.value)
  syncAppearanceState()
}

function setOption(option: AppearanceOption, enabled: boolean): void {
  appearance.setOption(option, enabled)
  // The controller couples liquid glass to the floating bar, so refresh every
  // option after a write instead of mirroring only the switch that was touched.
  syncAppearanceState()
}

onBeforeUnmount(appearance.onChange(syncAppearanceState))
</script>

<template>
  <section class="settings-view" aria-labelledby="settings-view-title">
    <MiuixTopAppBar :title="translate('settings_title', 'Settings')" />

    <div class="settings-content">
      <h1 id="settings-view-title" class="sr-only">
        {{ translate('settings_title', 'Settings') }}
      </h1>

      <section class="settings-section" aria-labelledby="language-title">
        <MiuixSmallTitle
          id="language-title"
          :text="translate('settings_language', 'Language')"
        />
        <MiuixCard class="settings-card settings-card--single" press-feedback="none">
          <MiuixDropdownPreference
            :model-value="languageIndex"
            :title="translate('settings_language', 'Language')"
            :items="languageItems"
            @update:model-value="selectLanguage"
          >
            <template #start>
              <span class="settings-preference-icon"><MiuixIcon :icon="Translate" :size="22" /></span>
            </template>
          </MiuixDropdownPreference>
        </MiuixCard>
      </section>

      <section class="settings-section" aria-labelledby="appearance-title">
        <MiuixSmallTitle
          id="appearance-title"
          :text="translate('settings_appearance', 'Appearance')"
        />
        <MiuixCard class="settings-card" press-feedback="none">
          <div class="mode-preference">
            <div class="preference-leading">
              <span class="settings-preference-icon"><MiuixIcon :icon="Theme" :size="22" /></span>
              <span class="mode-preference-title">{{ translate('settings_mode', 'Mode') }}</span>
            </div>
            <MiuixTabRow
              contour
              :model-value="modeIndex"
              :tabs="modeTabs"
              :aria-label="translate('settings_mode', 'Mode')"
              @update:model-value="selectMode"
            />
          </div>

          <div class="settings-divider"><MiuixDivider /></div>

          <MiuixSwitchPreference
            :model-value="options.monet"
            :title="translate('settings_monet', 'Enable Monet colors')"
            :summary="translate(
              'settings_monet_desc',
              'Generate dynamic colors from the system wallpaper',
            )"
            @update:model-value="setOption('monet', $event)"
          >
            <template #start>
              <span class="settings-preference-icon"><MiuixIcon :icon="Background" :size="22" /></span>
            </template>
          </MiuixSwitchPreference>

          <template v-if="options.monet">
            <div class="settings-divider"><MiuixDivider /></div>

            <MiuixSpinnerPreference
              :model-value="accentIndex"
              :title="translate('settings_color', 'Accent color')"
              :items="accentItems"
              @update:model-value="selectAccent"
            >
              <template #start>
                <span class="settings-preference-icon"><MiuixIcon :icon="Tune" :size="22" /></span>
              </template>
            </MiuixSpinnerPreference>
          </template>
        </MiuixCard>
      </section>

      <section class="settings-section" aria-labelledby="effects-title">
        <MiuixSmallTitle
          id="effects-title"
          :text="translate('settings_effects', 'Visual effects')"
        />
        <MiuixCard class="settings-card" press-feedback="none">
          <MiuixSwitchPreference
            :model-value="options.barBlur"
            :title="translate('settings_bar_blur', 'Top and bottom bar blur')"
            :summary="translate(
              'settings_bar_blur_desc',
              'Blur the background behind the app and navigation bars',
            )"
            @update:model-value="setOption('barBlur', $event)"
          >
            <template #start>
              <span class="settings-preference-icon"><MiuixIcon :icon="Layers" :size="22" /></span>
            </template>
          </MiuixSwitchPreference>

          <div class="settings-divider"><MiuixDivider /></div>

          <MiuixSwitchPreference
            :model-value="options.floatingBottomBar"
            :title="translate('settings_floating_bottom_bar', 'Floating bottom bar')"
            :summary="translate(
              'settings_floating_bottom_bar_desc',
              'Show navigation as a floating panel',
            )"
            @update:model-value="setOption('floatingBottomBar', $event)"
          >
            <template #start>
              <span class="settings-preference-icon"><MiuixIcon :icon="Sidebar" :size="22" /></span>
            </template>
          </MiuixSwitchPreference>

          <div class="settings-divider"><MiuixDivider /></div>

          <MiuixSwitchPreference
            :model-value="options.liquidGlass"
            :title="translate('settings_liquid_glass', 'Liquid glass')"
            :summary="translate(
              'settings_liquid_glass_desc',
              'Add translucent glass depth to surfaces',
            )"
            @update:model-value="setOption('liquidGlass', $event)"
          >
            <template #start>
              <span class="settings-preference-icon"><MiuixIcon :icon="Theme" :size="22" /></span>
            </template>
          </MiuixSwitchPreference>
        </MiuixCard>
      </section>
    </div>
  </section>
</template>

<style scoped>
.settings-view {
  min-height: 100%;
  color: var(--m-color-on-background);
}

.settings-view :deep(.m-top-app-bar) {
  background: transparent;
}

.settings-view :deep(.m-top-app-bar__row) {
  min-height: 64px;
}

.settings-view :deep(.m-top-app-bar__title .m-text) {
  font-size: clamp(21px, 5vw, 25px);
  font-weight: 700;
  letter-spacing: -.01em;
}

.settings-content {
  box-sizing: border-box;
  width: min(100%, 720px);
  margin: 0 auto;
  padding: 2px 12px 28px;
}

.settings-section + .settings-section {
  margin-top: 14px;
}

.settings-card {
  width: 100%;
}

.settings-card :deep(.m-card) {
  background: var(--m-color-primary-container);
  background: color-mix(
    in srgb,
    var(--m-color-primary-container) 14%,
    var(--m-color-surface-container)
  );
  border: 1px solid color-mix(in srgb, var(--m-color-primary) 8%, transparent);
  box-shadow: 0 2px 8px rgb(0 0 0 / 4%);
}

.settings-card--single :deep(.m-card) {
  min-height: 68px;
}

.mode-preference {
  box-sizing: border-box;
  display: grid;
  gap: 12px;
  padding: 16px;
}

.preference-leading {
  display: flex;
  align-items: center;
  gap: 12px;
}

.settings-preference-icon {
  display: inline-flex;
  flex: 0 0 28px;
  width: 28px;
  align-items: center;
  justify-content: center;
  color: var(--m-color-on-surface-variant-summary);
}

.mode-preference-title {
  display: block;
  color: var(--m-color-on-surface);
  font-size: 16px;
  font-weight: 600;
  line-height: 1.3;
}

.mode-preference :deep(.m-tab-row) {
  background: transparent;
}

.mode-preference :deep(.m-tab-row__scroll) {
  background: var(--m-color-surface-container-high);
  background: color-mix(
    in srgb,
    var(--m-color-primary-container) 18%,
    var(--m-color-surface-container-high)
  );
  min-height: 48px;
  border-radius: 24px;
}

.mode-preference :deep(.m-tab-row__indicator) {
  background: color-mix(in srgb, var(--m-color-primary) 16%, var(--m-color-surface-container));
  box-shadow: 0 2px 5px rgb(0 0 0 / 9%);
  border-radius: 20px;
}

.mode-preference :deep(.m-tab-row__item--selected) {
  color: var(--m-color-on-surface);
  font-weight: 600;
}

:global(:root.m-theme-dark) .mode-preference :deep(.m-tab-row__indicator) {
  background: var(--m-color-surface-container-highest);
  background: color-mix(
    in srgb,
    var(--m-color-surface-container-highest) 92%,
    var(--m-color-on-surface)
  );
  box-shadow: 0 1px 3px rgb(0 0 0 / 12%);
}

.settings-divider {
  padding-inline: 16px;
  opacity: .7;
}

.settings-card :deep(.m-basic-component) {
  min-height: 70px;
  padding: 12px 16px;
}

.settings-card :deep(.m-basic-component__start) {
  margin-inline-end: 4px;
}

.settings-card :deep(.m-basic-component__title) {
  font-size: 16px;
  font-weight: 600;
  line-height: 1.3;
}

.settings-card :deep(.m-basic-component__summary) {
  margin-top: 3px;
  font-size: 14px;
  line-height: 1.35;
}

.theme-preview {
  box-sizing: border-box;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 560px;
  margin: 0;
  padding: 32px 12px 72px;
  overflow: visible;
}

.preview-device {
  position: relative;
  display: flex;
  flex-direction: column;
  box-sizing: border-box;
  width: min(42%, 240px);
  aspect-ratio: .46;
  height: auto;
  padding: 14px 11px 12px;
  overflow: hidden;
  border: 2px solid color-mix(in srgb, var(--m-color-on-surface) 48%, transparent);
  border-radius: 36px;
  background: color-mix(in srgb, var(--m-color-surface) 94%, var(--m-color-primary));
  box-shadow: 0 3px 12px rgb(0 0 0 / 8%);
}

.preview-device-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 31px;
  padding-inline: 8px;
  color: var(--m-color-on-surface);
}

.preview-device-title {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: -.01em;
}

.preview-device-menu {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: color-mix(in srgb, var(--m-color-on-surface) 58%, transparent);
}

.preview-device-content {
  display: flex;
  flex: 1;
  flex-direction: column;
  gap: 10px;
  padding: 12px 0 14px;
}

.preview-device-accent,
.preview-device-panel {
  display: block;
  border-radius: 11px;
}

.preview-device-accent {
  height: 68px;
  background: color-mix(in srgb, var(--m-color-primary) 30%, var(--m-color-surface));
}

.preview-device-panel {
  flex: 1;
  background: color-mix(in srgb, var(--m-color-on-surface) 8%, var(--m-color-surface));
}

.preview-device-navigation {
  display: flex;
  align-items: center;
  justify-content: space-around;
  height: 44px;
  padding-inline: 8px;
  border: 1px solid color-mix(in srgb, var(--m-color-on-surface) 12%, transparent);
  border-radius: 22px;
  background: color-mix(in srgb, var(--m-color-surface-container-high) 90%, transparent);
  box-shadow: 0 1px 4px rgb(0 0 0 / 8%);
}

.preview-device-nav-item {
  display: block;
  width: 17px;
  height: 17px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--m-color-on-surface) 64%, transparent);
}

.preview-device-nav-item--active {
  background: var(--m-color-primary);
  box-shadow: 0 0 0 4px color-mix(in srgb, var(--m-color-primary) 14%, transparent);
}

:global(:root[data-bar-blur='true'] .preview-device-header),
:global(:root[data-bar-blur='true'] .preview-device-navigation) {
  -webkit-backdrop-filter: blur(12px);
  backdrop-filter: blur(12px);
}

:global(:root[data-liquid-glass='true'] .preview-device-navigation) {
  background: var(--omk-glass-background);
  -webkit-backdrop-filter: blur(10px) saturate(1.2);
  backdrop-filter: blur(10px) saturate(1.2);
  box-shadow: inset 0 0 0 1px rgb(255 255 255 / 9%), 0 1px 6px rgb(0 0 0 / 10%);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

@media (max-width: 420px) {
  .settings-content {
    padding-inline: 10px;
    padding-bottom: 22px;
  }

  .theme-preview {
    min-height: 390px;
    padding: 24px 8px 56px;
  }

  .mode-preference {
    padding: 12px 12px 14px;
  }

  .settings-divider {
    padding-inline: 12px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .preview-device-nav-item {
    transition: none;
  }
}
</style>

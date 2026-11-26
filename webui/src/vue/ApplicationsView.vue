<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import {
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
  MiuixSearchBar,
  MiuixSwitchPreference,
  MiuixTopAppBar,
  showSnackbar,
} from 'miuix-vue'
import {
  All,
  Back,
  ChevronForward,
  Clear,
  More,
  Play,
  Refresh,
  Reset,
  SelectAll,
  Sort,
  Tune,
} from 'miuix-vue/icons'
import type { AppEntry, AppList } from '../app_list/app_list'
import type { Cli } from '../cli'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'
import SoterIdentityDialog from './SoterIdentityDialog.vue'

interface Props {
  appList: AppList
  cli: Cli
  loading: boolean
  refreshing: boolean
  saving: boolean
  saveError: boolean
  applyEnabled: boolean
  active: boolean
  saveSelection: () => Promise<boolean>
  refresh: () => void
}

const props = defineProps<Props>()
const emit = defineEmits<{
  'overlay-open': []
  'overlay-close': []
  'profile-change': [open: boolean]
}>()

type SortField = 'name' | 'package'

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const revision = ref(props.appList.revision)
const searchQuery = ref('')
const appliedSearchQuery = ref('')
const showSystemApps = ref(false)
const sortField = ref<SortField>('name')
const descending = ref(false)
const menuOpen = ref(false)
const sortOpen = ref(false)
const profileMenuOpen = ref(false)
const appActionBusy = ref(false)
const selectedApp = ref<AppEntry | null>(null)
const renderedCount = ref(32)
const autoAddEnabled = ref(false)
const autoAddLoading = ref(false)
const autoAddLoaded = ref(false)
const autoAddBusy = ref(false)
const identityOpen = ref(false)
const identityTarget = ref('')
const identityLabel = ref('')
const identityBatchTargets = ref<string[] | undefined>()
const identityDialog = ref<InstanceType<typeof SoterIdentityDialog> | null>(null)
const unsubscribe = props.appList.subscribe(snapshot => { revision.value = snapshot.revision })
let searchTimer = 0

const entries = computed(() => {
  void revision.value
  const selected = new Set(props.appList.getSnapshot().selectedPackages)
  const installed = [...props.appList.getEntries()].sort((left, right) => {
    if (left.currentUser !== right.currentUser) return left.currentUser ? -1 : 1
    return left.userId - right.userId
  })

  const query = appliedSearchQuery.value.trim().toLocaleLowerCase()
  const result = installed
    .filter(entry => showSystemApps.value || !entry.isSystem)
    .filter(entry => !query
      || entry.appName.toLocaleLowerCase().includes(query)
      || entry.packageName.toLocaleLowerCase().includes(query))
    .sort((left, right) => {
      const compared = sortField.value === 'name'
        ? left.appName.localeCompare(right.appName, i18n.lang)
          || left.packageName.localeCompare(right.packageName)
        : left.packageName.localeCompare(right.packageName)
          || left.appName.localeCompare(right.appName, i18n.lang)
      const ordered = compared || left.userId - right.userId
      return descending.value ? -ordered : ordered
    })

  return result.map(entry => ({
    ...entry,
    selected: selected.has(entry.packageName) || selected.has(entry.targetKey),
  }))
})
const renderedEntries = computed(() => entries.value.slice(0, renderedCount.value))
const initialLoading = computed(() => props.loading && props.appList.getEntries().length === 0)

const activeSelection = computed(() => {
  void revision.value
  if (!selectedApp.value) return false
  const selected = new Set(props.appList.getSnapshot().selectedPackages)
  return selected.has(selectedApp.value.packageName) || selected.has(selectedApp.value.targetKey)
})

const activeApp = computed(() => selectedApp.value
  ? entries.value.find(entry => entry.targetKey === selectedApp.value?.targetKey) ?? selectedApp.value
  : null)
const profileCounts = computed(() => {
  const counts = new Map<string, number>()
  for (const entry of props.appList.getEntries()) {
    counts.set(entry.packageName, (counts.get(entry.packageName) ?? 0) + 1)
  }
  return counts
})

watch([menuOpen, sortOpen, profileMenuOpen, selectedApp, identityOpen], ([menu, sort, profileMenu, profile, identity], previous) => {
  const wasOpen = previous.some(Boolean)
  const isOpen = menu || sort || profileMenu || profile !== null || identity
  if (isOpen && !wasOpen) emit('overlay-open')
  else if (!isOpen && wasOpen) emit('overlay-close')
})

watch(() => props.active, active => {
  if (active && !autoAddLoaded.value && !autoAddLoading.value) void loadAutoAdd()
}, { immediate: true })
let renderFrame = 0
let renderTimer = 0
let renderGeneration = 0
watch([entries, () => props.active], ([items, active]) => {
  const generation = ++renderGeneration
  cancelAnimationFrame(renderFrame)
  clearTimeout(renderTimer)
  renderFrame = 0
  renderTimer = 0
  if (!active) {
    renderedCount.value = 0
    return
  }
  renderedCount.value = Math.min(Math.max(renderedCount.value, 32), items.length)
  const appendBatch = () => {
    if (generation !== renderGeneration || renderedCount.value >= items.length) return
    renderFrame = requestAnimationFrame(() => {
      renderTimer = window.setTimeout(() => {
        if (generation !== renderGeneration) return
        renderedCount.value = Math.min(renderedCount.value + 24, items.length)
        appendBatch()
      }, 0)
    })
  }
  appendBatch()
}, { immediate: true })
onBeforeUnmount(() => {
  window.clearTimeout(searchTimer)
  unsubscribe()
  renderGeneration++
  cancelAnimationFrame(renderFrame)
  clearTimeout(renderTimer)
})

watch(searchQuery, query => {
  window.clearTimeout(searchTimer)
  searchTimer = window.setTimeout(() => { appliedSearchQuery.value = query }, 120)
})

async function loadAutoAdd(): Promise<void> {
  autoAddLoading.value = true
  try {
    autoAddEnabled.value = isDev() ? autoAddEnabled.value : await props.cli.getAutoTargets()
    autoAddLoaded.value = true
  } catch (error) {
    void showSnackbar({
      message: error instanceof Error ? error.message : String(error),
      duration: 6000,
    })
  } finally {
    autoAddLoading.value = false
  }
}

async function setAutoAdd(enabled: boolean): Promise<void> {
  if (autoAddBusy.value || autoAddLoading.value) return
  autoAddBusy.value = true
  try {
    if (!isDev()) await props.cli.setAutoTargets(enabled)
    autoAddEnabled.value = isDev() ? enabled : await props.cli.getAutoTargets()
  } catch (error) {
    void showSnackbar({
      message: error instanceof Error ? error.message : String(error),
      duration: 6000,
    })
  } finally {
    autoAddBusy.value = false
  }
}

async function selectRecommended(): Promise<void> {
  if (!props.applyEnabled || props.loading || props.saving) return
  menuOpen.value = false
  try {
    await props.appList.selectRecommended()
    await props.saveSelection()
  } catch (error) {
    void showSnackbar({
      message: error instanceof Error ? error.message : String(error),
      duration: 6000,
    })
  }
}

async function deselectAll(): Promise<void> {
  if (!props.applyEnabled || props.loading || props.saving) return
  menuOpen.value = false
  props.appList.deselectAll()
  await props.saveSelection()
}

async function setApplicationEnabled(enabled: boolean): Promise<void> {
  const app = activeApp.value
  if (!app || props.loading || props.saving || !props.applyEnabled) return
  props.appList.setSelected(app.packageName, enabled)
  await props.saveSelection()
}

function openProfile(entry: AppEntry): void {
  menuOpen.value = false
  sortOpen.value = false
  profileMenuOpen.value = false
  selectedApp.value = entry
  emit('profile-change', true)
}

async function runApplicationAction(action: 'start' | 'stop' | 'restart'): Promise<void> {
  const app = activeApp.value
  if (!app || appActionBusy.value) return
  appActionBusy.value = true
  profileMenuOpen.value = false
  try {
    if (action === 'stop' || action === 'restart') {
      await props.cli.forceStopApplication(app.packageName, app.userId)
    }
    if (action === 'start' || action === 'restart') {
      await props.cli.startApplication(app.packageName, app.userId)
    }
  } catch (error) {
    void showSnackbar({
      message: error instanceof Error ? error.message : String(error),
      duration: 6000,
    })
  } finally {
    appActionBusy.value = false
  }
}

function showApplicationIcon(event: Event): void {
  const image = event.currentTarget as HTMLImageElement | null
  if (image) image.style.opacity = '1'
}

function openBulkIdentity(): void {
  if (props.loading || props.saving || !props.applyEnabled) return
  identityTarget.value = ''
  identityLabel.value = ''
  identityBatchTargets.value = props.appList.getSelectedIdentityTargets()
  menuOpen.value = false
  identityOpen.value = true
}

function closeProfile(): void {
  identityOpen.value = false
  selectedApp.value = null
  emit('profile-change', false)
}

function openSoterIdentity(): void {
  const app = activeApp.value
  if (!app) return
  identityTarget.value = app.targetKey
  identityLabel.value = app.appName
  identityBatchTargets.value = undefined
  identityOpen.value = true
}

function dismissOverlay(): boolean {
  if (identityOpen.value) {
    identityDialog.value?.requestClose()
    return true
  }
  if (menuOpen.value) {
    menuOpen.value = false
    return true
  }
  if (sortOpen.value) {
    sortOpen.value = false
    return true
  }
  if (profileMenuOpen.value) {
    profileMenuOpen.value = false
    return true
  }
  if (selectedApp.value) {
    closeProfile()
    return true
  }
  return false
}

function hasOverlay(): boolean {
  return menuOpen.value || sortOpen.value || selectedApp.value !== null || identityOpen.value
}

defineExpose({ dismissOverlay, hasOverlay })
</script>

<template>
  <section class="applications-view" :class="{ 'applications-view--profile': selectedApp !== null }" :aria-busy="loading">
    <div v-if="menuOpen || sortOpen || profileMenuOpen" class="applications-menu-scrim" @click="menuOpen = false; sortOpen = false; profileMenuOpen = false" />

    <div v-if="!selectedApp" class="applications-page">
      <header class="applications-header">
        <div class="applications-header__title">{{ translate('nav_apps', 'Applications') }}</div>
        <div class="applications-header__actions">
          <MiuixIconButton
            :aria-label="translate('app_sort_title', 'Sort apps')"
            :aria-expanded="sortOpen"
            @click="sortOpen = !sortOpen; menuOpen = false"
          >
            <MiuixIcon :icon="Sort" :size="23" />
          </MiuixIconButton>
          <MiuixIconButton
            :aria-label="translate('menu_more_options', 'More options')"
            :aria-expanded="menuOpen"
            @click="menuOpen = !menuOpen; sortOpen = false"
          >
            <MiuixIcon :icon="More" :size="23" />
          </MiuixIconButton>

          <Transition name="applications-menu">
            <MiuixCard v-if="sortOpen" class="applications-menu applications-sort-menu" role="menu">
              <button class="applications-menu__item" type="button" role="menuitemradio" :aria-checked="sortField === 'name'" @click="sortField = 'name'; sortOpen = false">
                <span>{{ translate('app_sort_name', 'App name') }}</span>
                <span v-if="sortField === 'name'" class="applications-menu__check">✓</span>
              </button>
              <button class="applications-menu__item" type="button" role="menuitemradio" :aria-checked="sortField === 'package'" @click="sortField = 'package'; sortOpen = false">
                <span>{{ translate('app_sort_package', 'Package name') }}</span>
                <span v-if="sortField === 'package'" class="applications-menu__check">✓</span>
              </button>
              <div class="applications-menu__divider" />
              <button class="applications-menu__item" type="button" role="menuitemcheckbox" :aria-checked="descending" @click="descending = !descending">
                {{ translate('app_sort_descending', 'Descending') }}
                <span v-if="descending" class="applications-menu__check">✓</span>
              </button>
            </MiuixCard>
          </Transition>
          <Transition name="applications-menu">
            <MiuixCard v-if="menuOpen" class="applications-menu" role="menu">
              <button class="applications-menu__item" type="button" role="menuitemcheckbox" :aria-checked="showSystemApps" @click="showSystemApps = !showSystemApps">
                {{ translate('app_show_system_apps', 'Show system apps') }}
                <span v-if="showSystemApps" class="applications-menu__check">✓</span>
              </button>
              <div class="applications-menu__divider" />
              <button class="applications-menu__item" type="button" role="menuitemcheckbox" :aria-checked="autoAddEnabled" :disabled="loading || saving || autoAddLoading || autoAddBusy" @click="setAutoAdd(!autoAddEnabled)">
                <span>{{ translate('app_targets_auto_title', 'Automatically add new apps') }}</span>
                <span class="applications-menu__check" :class="{ 'applications-menu__check--off': !autoAddEnabled }">{{ autoAddLoading ? '…' : autoAddEnabled ? '✓' : '○' }}</span>
              </button>
              <button class="applications-menu__item" type="button" role="menuitem" :disabled="loading || saving" @click="selectRecommended">
                <MiuixIcon :icon="SelectAll" :size="20" />
                {{ translate('menu_select_all', 'Select recommended apps') }}
              </button>
              <button class="applications-menu__item" type="button" role="menuitem" :disabled="loading || saving" @click="deselectAll">
                <MiuixIcon :icon="Clear" :size="20" />
                {{ translate('menu_deselect_all', 'Deselect all') }}
              </button>
              <button class="applications-menu__item" type="button" role="menuitem" :disabled="loading || saving || !applyEnabled" @click="openBulkIdentity">
                <MiuixIcon :icon="Tune" :size="20" />
                {{ translate('soter_bulk_title', 'Assign local identity to selected apps') }}
              </button>
              <button class="applications-menu__item" type="button" role="menuitem" :disabled="loading || refreshing || saving" @click="menuOpen = false; refresh()">
                <MiuixIcon :icon="Refresh" :size="20" />
                {{ translate('menu_refresh', 'Refresh') }}
              </button>
            </MiuixCard>
          </Transition>
        </div>
      </header>

      <MiuixSearchBar
        v-model="searchQuery"
        :label="translate('app_targets_filter_aria', 'Search apps')"
        :cancel-text="translate('functional_button_cancel', 'Cancel')"
      />

      <div v-if="saving || saveError" class="applications-state" :role="saveError ? 'alert' : 'status'">
        <MiuixProgressIndicator v-if="saving" type="circular" :size="18" />
        <span>{{ translate(saveError ? 'app_targets_save_failed' : 'app_targets_saving', saveError ? 'Could not save app settings. Retry.' : 'Saving app settings…') }}</span>
        <MiuixButton v-if="saveError" @click="props.saveSelection">{{ translate('functional_button_retry', 'Retry') }}</MiuixButton>
      </div>

      <div v-if="initialLoading" class="applications-empty" role="status">
        <MiuixProgressIndicator type="circular" :size="32" />
      </div>
      <div v-else-if="entries.length" class="applications-list">
        <button
          v-for="entry in renderedEntries"
          :key="entry.targetKey"
          type="button"
          class="application-row"
          @click="openProfile(entry)"
        >
          <span class="application-row__icon-frame">
            <img :src="`ksu://icon/${entry.packageName}`" :alt="entry.appName" loading="lazy" decoding="async" @load="showApplicationIcon">
            <MiuixIcon :icon="All" :size="18" />
          </span>
          <span class="application-row__body">
            <span class="application-row__name">{{ entry.appName }}</span>
            <span class="application-row__package">
              {{ entry.packageName }}
              <span v-if="(profileCounts.get(entry.packageName) ?? 0) > 1" class="application-row__user">
                {{ translate('app_user_label', 'User') }} {{ entry.userId }}
              </span>
            </span>
          </span>
          <span class="application-row__state" :class="entry.selected ? 'application-row__state--enabled' : 'application-row__state--disabled'">
            {{ entry.selected ? translate('app_omk_enabled', 'OMK') : translate('app_omk_disabled', 'Not added') }}
          </span>
          <MiuixIcon class="application-row__arrow" :icon="ChevronForward" :size="20" />
        </button>
        <div v-if="renderedEntries.length < entries.length" class="applications-list__loading" role="status">
          <MiuixProgressIndicator type="circular" :size="22" />
        </div>
      </div>
      <div v-else class="applications-empty">
        <MiuixIcon :icon="All" :size="34" />
        <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
      </div>
    </div>

    <div v-else-if="activeApp" class="application-profile">
      <MiuixTopAppBar :title="translate('app_profile_title', 'App Profile')" color="transparent">
        <template #navigation>
          <MiuixIconButton :aria-label="translate('functional_button_back', 'Back')" @click="closeProfile">
            <MiuixIcon :icon="Back" :size="24" />
          </MiuixIconButton>
        </template>
        <template #actions>
          <div class="applications-header__actions">
            <MiuixIconButton :aria-label="translate('menu_more_options', 'More options')" :aria-expanded="profileMenuOpen" @click="profileMenuOpen = !profileMenuOpen">
              <MiuixIcon :icon="More" :size="23" />
            </MiuixIconButton>
            <Transition name="applications-menu">
              <MiuixCard v-if="profileMenuOpen" class="applications-menu application-profile__menu" role="menu">
                <button class="applications-menu__item" type="button" role="menuitem" :disabled="appActionBusy" @click="runApplicationAction('start')">
                  <MiuixIcon :icon="Play" :size="20" />
                  {{ translate('app_action_start', 'Start') }}
                </button>
                <button class="applications-menu__item" type="button" role="menuitem" :disabled="appActionBusy" @click="runApplicationAction('stop')">
                  <MiuixIcon :icon="Clear" :size="20" />
                  {{ translate('app_action_force_stop', 'Force stop') }}
                </button>
                <button class="applications-menu__item" type="button" role="menuitem" :disabled="appActionBusy" @click="runApplicationAction('restart')">
                  <MiuixIcon :icon="Reset" :size="20" />
                  {{ translate('app_action_restart', 'Restart') }}
                </button>
              </MiuixCard>
            </Transition>
          </div>
        </template>
      </MiuixTopAppBar>

      <MiuixCard class="application-profile__identity" press-feedback="none">
        <div class="application-profile__identity-row">
          <span class="application-profile__icon-frame">
            <img :src="`ksu://icon/${activeApp.packageName}`" :alt="activeApp.appName" decoding="async" @load="showApplicationIcon">
            <MiuixIcon :icon="All" :size="22" />
          </span>
          <span class="application-profile__identity-text">
            <strong>{{ activeApp.appName }}</strong>
            <span v-if="activeApp.versionName">{{ activeApp.versionName }}</span>
            <span>{{ activeApp.packageName }}</span>
          </span>
          <span v-if="activeApp.uid !== null" class="application-profile__uid">UID {{ activeApp.uid }}</span>
        </div>
      </MiuixCard>

      <MiuixCard class="application-profile__section" press-feedback="none">
        <MiuixSwitchPreference
          :model-value="activeSelection"
          :disabled="loading || saving || !applyEnabled"
          :title="translate('app_omk_scope_title', 'OMK app scope')"
          @update:model-value="setApplicationEnabled"
        />
      </MiuixCard>

      <MiuixCard class="application-profile__section" press-feedback="none">
        <button type="button" class="application-profile__action" :disabled="loading || saving || !applyEnabled" @click="openSoterIdentity">
          <span class="application-profile__action-icon"><MiuixIcon :icon="Tune" :size="22" /></span>
          <span class="application-profile__action-copy">
            <strong>{{ translate('soter_app_identity', 'SOTER identity') }}</strong>
            <small>{{ translate('soter_app_identity_desc', 'Configure the identity used by this app.') }}</small>
          </span>
          <MiuixIcon :icon="ChevronForward" :size="20" />
        </button>
      </MiuixCard>
    </div>

    <SoterIdentityDialog
      ref="identityDialog"
      v-model="identityOpen"
      :cli="cli"
      :target="identityTarget"
      :target-label="identityLabel"
      :batch-targets="identityBatchTargets"
    />
  </section>
</template>

<style scoped>
.applications-view { min-height: 100%; color: var(--m-color-on-background); background: var(--m-color-surface); }
.applications-page { min-height: 100%; padding-bottom: calc(100px / var(--omk-ui-scale)); }
.application-profile { min-height: 100%; padding-bottom: 20px; }
.applications-header { position: sticky; z-index: 20; top: 0; display: flex; align-items: center; justify-content: space-between; gap: 8px; min-height: 70px; padding: calc(var(--omk-top-inset) / var(--omk-ui-scale)) 20px 0; background: var(--m-color-surface); }
.applications-header__title { min-width: 0; color: var(--m-color-on-background); font-size: clamp(27px, 7vw, 34px); font-weight: 650; letter-spacing: -0.04em; }
.applications-header__actions { position: relative; display: flex; flex: none; align-items: center; }
.applications-menu-scrim { position: fixed; z-index: 40; inset: 0; }
.applications-menu { position: absolute; z-index: 50; top: calc(100% + 8px); inset-inline-end: 0; width: min(300px, calc(100vw - 28px)); min-width: min(300px, calc(100vw - 28px)); max-height: min(70dvh, 620px); overflow: auto; padding: 6px; border: 1px solid color-mix(in srgb, var(--m-color-on-surface) 8%, transparent); border-radius: 20px; background: var(--m-color-surface-container); box-shadow: 0 14px 36px rgb(0 0 0 / 16%); }
.applications-menu__item { display: flex; width: 100%; min-height: 46px; align-items: center; gap: 12px; padding: 8px 12px; border: 0; border-radius: 13px; background: transparent; color: var(--m-color-on-surface); text-align: start; font: inherit; }
.applications-menu__item:active { background: color-mix(in srgb, var(--m-color-on-surface) 8%, transparent); }
.applications-menu__item:disabled { opacity: .45; }
.applications-menu__check { margin-inline-start: auto; color: var(--m-color-primary); font-weight: 700; }
.applications-menu__check--off { color: var(--m-color-on-surface-variant-summary); }
.applications-menu__divider { height: 1px; margin: 5px 10px; background: var(--m-color-outline-variant); }
.applications-list { display: grid; gap: 12px; padding: 10px 18px 28px; }
.applications-list__loading { display: grid; justify-items: center; padding: 14px; }
.application-row { display: flex; width: 100%; min-height: 60px; align-items: center; gap: 12px; padding: 9px 12px; border: 0; border-radius: 16px; background: var(--m-color-surface-container-low, var(--m-color-surface-container)); color: var(--m-color-on-surface); text-align: start; font: inherit; -webkit-tap-highlight-color: transparent; }
.application-row:active { background: var(--m-color-surface-container-high); }
.application-row__icon-frame, .application-profile__icon-frame { position: relative; display: grid; flex: none; place-items: center; overflow: hidden; color: var(--m-color-on-tertiary-container); background: var(--m-color-tertiary-container); }
.application-row__icon-frame { width: 40px; height: 40px; border-radius: 12px; }
.application-row__icon-frame img, .application-profile__icon-frame img { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; opacity: 0; }
.application-row__body { display: grid; flex: 1; min-width: 0; gap: 4px; }
.application-row__name, .application-row__package { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.application-row__name { font-size: 15px; font-weight: 600; }
.application-row__package { color: var(--m-color-on-surface-variant-summary); font-size: 11.5px; }
.application-row__state { flex: none; padding: 2px 8px; border-radius: 999px; font-size: 10.5px; font-weight: 700; }
.application-row__state--enabled { color: var(--m-color-primary); background: color-mix(in srgb, var(--m-color-primary) 12%, transparent); }
.application-row__state--disabled { color: var(--m-color-on-surface-variant-summary); background: color-mix(in srgb, var(--m-color-on-surface) 10%, transparent); }
.application-row__arrow { flex: none; color: var(--m-color-on-surface-variant-summary); }
.applications-empty { display: grid; min-height: 210px; place-content: center; justify-items: center; gap: 12px; color: var(--m-color-on-surface-variant-summary); }
.applications-state { display: flex; align-items: center; justify-content: center; gap: 10px; padding: 10px 18px; color: var(--m-color-on-surface-variant-summary); }
.application-profile :deep(.m-top-app-bar) { padding-top: calc(var(--omk-top-inset) / var(--omk-ui-scale)); }
.application-profile__identity { margin: 12px 16px 14px; padding: 12px 16px; border-radius: 20px; background: var(--m-color-surface-container-low, var(--m-color-surface-container)); }
.application-profile__identity-row { display: flex; align-items: center; gap: 14px; width: 100%; min-width: 0; }
.application-profile__menu { top: calc(100% + 4px); }
.application-profile__icon-frame { width: 52px; height: 52px; border-radius: 16px; }
.application-profile__identity-text { display: grid; flex: 1; min-width: 0; gap: 4px; }
.application-profile__identity-text strong { font-size: 17px; font-weight: 650; }
.application-profile__identity-text span { overflow: hidden; color: var(--m-color-on-surface-variant-summary); font-size: 11.5px; text-overflow: ellipsis; white-space: nowrap; }
.application-profile__uid { flex: none; padding: 3px 9px; border-radius: 999px; color: var(--m-color-primary); background: color-mix(in srgb, var(--m-color-primary) 12%, transparent); font-size: 11px; font-weight: 700; }
.application-profile__section { margin: 0 16px 10px; overflow: hidden; border-radius: 18px; background: var(--m-color-surface-container-low, var(--m-color-surface-container)); }
.application-profile__action { display: flex; width: 100%; min-height: 56px; align-items: center; gap: 12px; padding: 8px 14px; border: 0; background: transparent; color: var(--m-color-on-surface); text-align: start; font: inherit; }
.application-profile__action:disabled { opacity: .5; }
.application-profile__action-icon { display: grid; width: 30px; place-items: center; color: var(--m-color-on-surface-variant-summary); }
.application-profile__action-copy { display: grid; flex: 1; gap: 4px; }
.application-profile__action-copy strong { font-size: 17px; font-weight: 550; }
.application-profile__action-copy small { color: var(--m-color-on-surface-variant-summary); font-size: 13px; }
</style>

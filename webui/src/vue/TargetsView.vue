<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { ComponentPublicInstance, ComputedRef } from 'vue'
import {
  MiuixBottomSheet,
  MiuixButton,
  MiuixCard,
  MiuixCheckboxPreference,
  MiuixFloatingActionButton,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
  MiuixSearchBar,
  MiuixSwitchPreference,
  MiuixTopAppBar,
  showSnackbar,
} from 'miuix-vue'
import {
  AddCircle,
  All,
  Back,
  Clear,
  Close,
  More,
  Ok,
  Refresh,
  SelectAll,
} from 'miuix-vue/icons'
import {
  afterPaint,
  parsePackageUserTarget,
  type AppList,
  type SelectableAppEntry,
} from '../app_list/app_list'
import { type Cli, type SoterHalState } from '../cli'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

interface Props {
  appList: AppList
  cli: Cli
  loading?: boolean
  refreshing?: boolean
  applyEnabled?: boolean
}

interface SearchBarInstance extends ComponentPublicInstance {
  $el: HTMLElement
}

type IconState = 'loading' | 'loaded' | 'error'

const props = withDefaults(defineProps<Props>(), {
  loading: false,
  refreshing: false,
  applyEnabled: true,
})

const emit = defineEmits<{
  close: []
  apply: []
  refresh: []
  'overlay-open': []
  'overlay-close': []
}>()

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const revision = ref(props.appList.revision)
const searchQuery = ref('')
const searchExpanded = ref(false)
const menuOpen = ref(false)
const selectingRecommended = ref(false)
const systemSheetOpen = ref(false)
const systemSearchQuery = ref('')
const systemSelection = ref(new Set<string>())
const iconStates = ref<Record<string, IconState>>({})
const searchBar = ref<SearchBarInstance | null>(null)
const pullBody = ref<HTMLElement | null>(null)
const pullIndicator = ref<HTMLElement | null>(null)
const pullCapsule = ref<HTMLElement | null>(null)
const pullActive = ref(false)
const pullReady = ref(false)
const autoEnabled = ref(false)
const autoStatus = ref<'loading' | 'ready' | 'error'>('loading')
const autoBusy = ref(false)
const autoError = ref('')
const appSheetOpen = ref(false)
const appSettingsEntry = ref<SelectableAppEntry | null>(null)
const appSettingsStatus = ref<'loading' | 'ready' | 'error'>('loading')
const appSettingsBusy = ref(false)
const appSettingsError = ref('')
const soterSelection = ref<Pick<SoterHalState, 'enabled' | 'remote_enabled' | 'app_enabled' | 'app_targets'> | null>(null)
let appSettingsGeneration = 0
let returnToSystemSheet = false
let disposed = false

const appSoterSelected = computed(() => !!appSettingsEntry.value
  && soterSelection.value?.app_targets.includes(appSettingsEntry.value.targetKey) === true)
const appSoterReady = computed(() => soterSelection.value?.app_enabled === true
  && soterSelection.value.remote_enabled && !soterSelection.value.enabled)

function retainSoterSelection(state: SoterHalState): void {
  soterSelection.value = {
    enabled: state.enabled,
    remote_enabled: state.remote_enabled,
    app_enabled: state.app_enabled,
    app_targets: [...state.app_targets],
  }
}

async function loadAppSettings(): Promise<void> {
  if (!appSheetOpen.value || appSettingsBusy.value) return
  const currentGeneration = ++appSettingsGeneration
  appSettingsStatus.value = 'loading'
  appSettingsError.value = ''
  try {
    await afterPaint()
    if (disposed || currentGeneration !== appSettingsGeneration || !appSheetOpen.value) return
    if (isDev()) {
      soterSelection.value ??= { enabled: false, remote_enabled: false, app_enabled: false, app_targets: [] }
    } else {
      const state = await props.cli.getSoterHal()
      if (disposed || currentGeneration !== appSettingsGeneration || !appSheetOpen.value) return
      retainSoterSelection(state)
    }
    appSettingsStatus.value = 'ready'
  } catch {
    if (disposed || currentGeneration !== appSettingsGeneration || !appSheetOpen.value) return
    appSettingsStatus.value = 'error'
    appSettingsError.value = translate('soter_app_load_error', 'Unable to read app SOTER settings. Check that the installed module is up to date.')
  }
}

function openAppSettings(entry: SelectableAppEntry): void {
  if (props.loading || appSettingsBusy.value) return
  returnToSystemSheet = systemSheetOpen.value
  systemSheetOpen.value = false
  menuOpen.value = false
  appSettingsEntry.value = entry
  appSheetOpen.value = true
  void loadAppSettings()
}

function closeAppSettings(): void {
  if (appSettingsBusy.value) return
  appSettingsGeneration++
  appSheetOpen.value = false
  if (returnToSystemSheet) systemSheetOpen.value = true
  returnToSystemSheet = false
}

async function setAppSoter(enabled: boolean): Promise<void> {
  const entry = appSettingsEntry.value
  if (!entry || appSettingsBusy.value || appSettingsStatus.value !== 'ready' || isDev()) return
  appSettingsBusy.value = true
  appSettingsError.value = ''
  try {
    const state = await props.cli.setSoterAppTarget(entry.targetKey, enabled)
    if (disposed) return
    retainSoterSelection(state)
    void showSnackbar({ message: translate('soter_app_saved', 'App SOTER selection saved') })
  } catch {
    if (!disposed) {
      appSettingsError.value = translate('soter_app_save_error', 'Unable to save this app SOTER selection. Retry to read the current setting.')
      // A failed read-back can follow a successful write. Do not leave a
      // stale switch actionable until the actual device state is reloaded.
      appSettingsStatus.value = 'error'
    }
  } finally {
    appSettingsBusy.value = false
  }
}

async function loadAutoTargets(): Promise<void> {
  autoStatus.value = 'loading'
  autoError.value = ''
  try {
    const enabled = isDev() ? autoEnabled.value : await props.cli.getAutoTargets()
    if (disposed) return
    autoEnabled.value = enabled
    autoStatus.value = 'ready'
  } catch (error) {
    if (disposed) return
    autoStatus.value = 'error'
    autoError.value = error instanceof Error ? error.message : String(error)
  }
}

async function setAutoTargets(enabled: boolean): Promise<void> {
  if (autoBusy.value || autoStatus.value !== 'ready') return
  autoBusy.value = true
  autoError.value = ''
  try {
    if (!isDev()) await props.cli.setAutoTargets(enabled)
    autoEnabled.value = enabled
    void showSnackbar({ message: translate('app_targets_auto_saved', 'Automatic selection setting saved') })
  } catch (error) {
    autoError.value = error instanceof Error ? error.message : String(error)
  } finally {
    autoBusy.value = false
  }
}

onMounted(() => { void loadAutoTargets() })
let pullStart: { x: number, y: number, offset: number, scale: number } | null = null
let pullDistance = 0
let pullCaptured = false
let pullFrame = 0
const PULL_REFRESH_DISTANCE = 80
const PULL_REFRESH_OFFSET = 64

// Keep continuous gesture updates outside Vue's render effect. Only the
// threshold/refresh state changes render; the app rows do not update per pixel.
function paintPull(): void {
  if (pullBody.value) pullBody.value.style.transform = `translate3d(0, ${pullDistance}px, 0)`
  if (pullIndicator.value) {
    pullIndicator.value.style.transform = `translate3d(0, ${pullDistance - PULL_REFRESH_OFFSET}px, 0)`
    pullIndicator.value.style.opacity = String(Math.min(1, pullDistance / 48))
  }
  if (pullCapsule.value) {
    pullCapsule.value.style.setProperty('--pull-stretch', String(Math.max(0, pullDistance - 62)))
  }
}

function settlePull(distance: number): void {
  cancelAnimationFrame(pullFrame)
  pullFrame = 0
  pullStart = null
  pullCaptured = false
  pullActive.value = false
  pullReady.value = false
  pullDistance = distance
  for (const element of [pullBody.value, pullIndicator.value, pullCapsule.value]) {
    if (element) element.style.transition = ''
  }
  paintPull()
}

function resetPull(): void {
  settlePull(props.refreshing ? PULL_REFRESH_OFFSET : 0)
}

function startPull(event: TouchEvent): void {
  if (props.loading || selectingRecommended.value || menuOpen.value || systemSheetOpen.value || appSheetOpen.value
      || event.touches.length !== 1 || (document.scrollingElement?.scrollTop ?? window.scrollY) > 0
      || (event.target instanceof Element && event.target.closest('input, button, [role="switch"]'))) {
    if (pullStart) resetPull()
    return
  }
  cancelAnimationFrame(pullFrame)
  pullFrame = 0
  // A second drag can start during the return animation. Read its displayed
  // offset once, then freeze it instead of jumping back to the logical target.
  const transform = pullBody.value ? getComputedStyle(pullBody.value).transform : 'none'
  const offset = transform === 'none' ? 0 : Math.max(0, new DOMMatrixReadOnly(transform).m42)
  const scale = Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--omk-ui-scale')) || 1
  const touch = event.touches[0]!
  pullStart = { x: touch.clientX, y: touch.clientY, offset, scale }
  pullCaptured = false
  pullDistance = offset
  for (const element of [pullBody.value, pullIndicator.value, pullCapsule.value]) {
    if (element) element.style.transition = 'none'
  }
  paintPull()
}

function movePull(event: TouchEvent): void {
  if (!pullStart) return
  if (event.touches.length !== 1) { resetPull(); return }
  const touch = event.touches[0]!
  const dy = touch.clientY - pullStart.y
  if (dy < 0 || Math.abs(touch.clientX - pullStart.x) > Math.max(12, dy)) {
    resetPull()
    return
  }
  if (!pullCaptured) {
    if (dy <= 8) return
    if (!event.cancelable || (document.scrollingElement?.scrollTop ?? window.scrollY) > 0) {
      resetPull()
      return
    }
    pullCaptured = true
    pullActive.value = true
  }
  if (event.cancelable) event.preventDefault()
  const distance = dy * 0.5 / pullStart.scale
  pullDistance = Math.min(144, pullStart.offset + (distance <= PULL_REFRESH_DISTANCE
    ? distance : PULL_REFRESH_DISTANCE + (distance - PULL_REFRESH_DISTANCE) * 0.35))
  pullReady.value = pullDistance >= PULL_REFRESH_DISTANCE
  if (!pullFrame) {
    pullFrame = requestAnimationFrame(() => {
      pullFrame = 0
      paintPull()
    })
  }
}

function finishPull(event: TouchEvent): void {
  if (!pullStart) return
  // Use the latest logical distance even if its animation frame has not run.
  const ready = pullCaptured && pullDistance >= PULL_REFRESH_DISTANCE
  if (pullCaptured && event.cancelable) event.preventDefault()
  settlePull(ready ? PULL_REFRESH_OFFSET : 0)
  if (ready) refresh()
}

watch(() => props.refreshing, refreshing => {
  settlePull(refreshing ? PULL_REFRESH_OFFSET : 0)
})
// A menu followed by the system sheet is one overlay in the parent's history.
// Watching the combined state also avoids closing a second layer on Android Back.
watch(() => menuOpen.value || systemSheetOpen.value || appSheetOpen.value, open => {
  if (open) emit('overlay-open')
  else emit('overlay-close')
})

const unsubscribe = props.appList.subscribe(snapshot => {
  revision.value = snapshot.revision
})

const targetEntries = computed(() => {
  void revision.value
  return props.appList.getTargetEntries(searchQuery.value)
})
const systemEntries = computed(() => {
  void revision.value
  return props.appList.getSystemEntries(systemSearchQuery.value)
})
const showUserGroups = computed(() => {
  void revision.value
  return new Set(props.appList.getEntries().map(entry => entry.userId)).size > 1
})
const initialLoading = computed(() => {
  void revision.value
  return props.loading && props.appList.getEntries().length === 0
})

// MIUIX preferences include animated controls. Mount a small batch per paint so
// hundreds of installed packages cannot block the sheet or navigation animation.
function batchedEntries(
  entries: ComputedRef<SelectableAppEntry[]>,
  enabled: ComputedRef<boolean>,
): ComputedRef<SelectableAppEntry[]> {
  const count = ref(0)
  let frame = 0
  let timer = 0
  let generation = 0
  const cancel = () => {
    generation++
    cancelAnimationFrame(frame)
    clearTimeout(timer)
  }
  watch([entries, enabled], ([items, active]) => {
    cancel()
    if (!active) {
      count.value = 0
      return
    }
    count.value = Math.min(Math.max(count.value, 16), items.length)
    const currentGeneration = generation
    const append = () => {
      if (currentGeneration !== generation || count.value >= items.length) return
      frame = requestAnimationFrame(() => {
        timer = window.setTimeout(() => {
          if (currentGeneration !== generation) return
          count.value = Math.min(count.value + 16, items.length)
          append()
        }, 0)
      })
    }
    append()
  }, { immediate: true })
  onBeforeUnmount(cancel)
  return computed(() => entries.value.slice(0, count.value))
}

const renderedTargetEntries = batchedEntries(targetEntries, computed(() => true))
const renderedSystemEntries = batchedEntries(
  systemEntries,
  computed(() => systemSheetOpen.value),
)

function iconState(packageName: string): IconState {
  return iconStates.value[packageName] ?? 'loading'
}

function setIconState(packageName: string, state: IconState): void {
  if (iconStates.value[packageName] === state) return
  iconStates.value[packageName] = state
}

function setSelected(entry: SelectableAppEntry, selected: boolean): void {
  if (props.loading || menuOpen.value || selectingRecommended.value) return
  props.appList.setTargetSelected(entry, selected)
}

async function selectRecommended(): Promise<void> {
  if (props.loading || selectingRecommended.value) return
  selectingRecommended.value = true
  try {
    await props.appList.selectRecommended()
    menuOpen.value = false
  } catch (error) {
    console.error('Unable to select recommended apps:', error)
    void showSnackbar({
      message: translate('prompt_load_error', 'Unable to load apps. Please refresh and try again.'),
      duration: 'long',
      withDismissAction: true,
    })
  } finally {
    selectingRecommended.value = false
  }
}

function deselectAll(): void {
  menuOpen.value = false
  props.appList.deselectAll()
}

function refresh(): void {
  if (props.loading || selectingRecommended.value) return
  menuOpen.value = false
  emit('refresh')
}

function apply(): void {
  if (!props.loading && !selectingRecommended.value && props.applyEnabled) emit('apply')
}

function focusSearch(): void {
  searchExpanded.value = true
  requestAnimationFrame(() => {
    searchBar.value?.$el.querySelector<HTMLInputElement>('input[type="search"]')?.focus()
  })
}

function openSystemApps(): void {
  menuOpen.value = false
  systemSearchQuery.value = ''
  // Retain bare all-user rules and unmapped selectors instead of converting
  // them to the currently visible profile list when the sheet is opened.
  systemSelection.value = new Set(props.appList.getSelectedPackages())
  systemSheetOpen.value = true
}

function setSystemSelected(targetKey: string, selected: boolean): void {
  const target = parsePackageUserTarget(targetKey)
  if (target === null) return
  const nextSelection = new Set(systemSelection.value)
  if (selected) {
    if (!nextSelection.has(target.packageName)) nextSelection.add(target.targetKey)
  } else {
    nextSelection.delete(target.targetKey)
    if (nextSelection.delete(target.packageName)) {
      for (const entry of props.appList.getSystemEntries()) {
        if (entry.packageName === target.packageName && entry.userId !== target.userId) {
          nextSelection.add(entry.targetKey)
        }
      }
    }
  }
  systemSelection.value = nextSelection
}

function saveSystemApps(): void {
  if (props.loading) return
  props.appList.applySystemAppSelection([...systemSelection.value])
  systemSheetOpen.value = false
}

function closeSystemApps(): void {
  systemSheetOpen.value = false
}

function dismissOverlay(): boolean {
  if (appSheetOpen.value) {
    closeAppSettings()
    return true
  }
  if (systemSheetOpen.value) {
    closeSystemApps()
    return true
  }
  if (menuOpen.value) {
    menuOpen.value = false
    return true
  }
  return false
}

onBeforeUnmount(() => {
  disposed = true
  appSettingsGeneration++
  cancelAnimationFrame(pullFrame)
  unsubscribe()
})

defineExpose({
  focusSearch,
  selectRecommended,
  deselectAll,
  refresh,
  apply,
  openSystemApps,
  dismissOverlay,
})
</script>

<template>
  <section
    class="targets-view"
    aria-labelledby="targets-view-title"
    @touchstart.passive="startPull"
    @touchmove="movePull"
    @touchend="finishPull"
    @touchcancel="resetPull"
  >
    <div v-if="menuOpen" class="targets-menu-scrim" @click="menuOpen = false" />
    <div class="targets-top-bar">
      <MiuixTopAppBar
        id="targets-view-title"
        :title="translate('app_targets_title', 'Add package names')"
        color="transparent"
      >
        <template #navigation>
          <MiuixIconButton
            :aria-label="translate('functional_button_back', 'Back')"
            @click="emit('close')"
          >
            <MiuixIcon :icon="Back" />
          </MiuixIconButton>
        </template>

        <template #actions>
          <div class="targets-menu">
            <MiuixIconButton
              class="targets-menu-toggle"
              :hold-down="menuOpen"
              :aria-label="translate('menu_more_options', 'More options')"
              aria-haspopup="menu"
              :aria-expanded="menuOpen"
              @click.stop="menuOpen = !menuOpen"
            >
              <MiuixIcon :icon="More" />
            </MiuixIconButton>

            <Transition name="targets-menu">
              <MiuixCard v-if="menuOpen" class="targets-menu-popup" role="menu">
                <MiuixButton role="menuitem" :disabled="loading || selectingRecommended" @click="selectRecommended">
                  <MiuixProgressIndicator v-if="selectingRecommended" type="circular" :size="21" />
                  <MiuixIcon v-else :icon="SelectAll" :size="21" />
                  <span class="targets-menu-label">
                    <span>{{ translate('menu_select_all', 'Select recommended apps') }}</span>
                    <small>{{ translate('menu_select_recommended_desc', 'User apps and Google services; skip recognized Root, Shizuku and Xposed tools. Keep existing selections.') }}</small>
                  </span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="selectingRecommended" @click="deselectAll">
                  <MiuixIcon :icon="Clear" :size="21" />
                  <span>{{ translate('menu_deselect_all', 'Deselect all') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="loading || selectingRecommended" @click="refresh">
                  <MiuixIcon :icon="Refresh" :size="21" />
                  <span>{{ translate('menu_refresh', 'Refresh') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="loading || selectingRecommended" @click="openSystemApps">
                  <MiuixIcon :icon="AddCircle" :size="21" />
                  <span>{{ translate('menu_add_system_app', 'Add System App') }}</span>
                </MiuixButton>
              </MiuixCard>
            </Transition>
          </div>
        </template>
      </MiuixTopAppBar>

      <MiuixSearchBar
        ref="searchBar"
        v-model="searchQuery"
        v-model:expanded="searchExpanded"
        :label="translate('search_bar_search_placeholder', 'Search')"
        :cancel-text="translate('functional_button_cancel', 'Cancel')"
        @focusin="menuOpen = false"
      />

    </div>

    <main class="targets-content" :aria-busy="loading">
      <div ref="pullIndicator" class="targets-pull"
        :class="{ 'targets-pull--refreshing': refreshing }"
        :aria-hidden="!pullActive && !refreshing" role="status" aria-live="polite">
        <div class="targets-pull-content">
          <MiuixProgressIndicator v-if="refreshing" type="circular" :size="24" :stroke-width="2.5" />
          <span v-show="!refreshing" ref="pullCapsule" class="targets-pull-capsule" aria-hidden="true">
            <span class="targets-pull-stem" />
          </span>
          <span>{{ refreshing
            ? translate('app_targets_refreshing', 'Refreshing')
            : pullReady
              ? translate('app_targets_release_refresh', 'Release to refresh')
              : translate('app_targets_pull_refresh', 'Pull down to refresh apps') }}</span>
        </div>
      </div>
      <div ref="pullBody" class="targets-pull-body">
      <MiuixCard class="targets-auto" press-feedback="none">
        <MiuixSwitchPreference
          :model-value="autoEnabled"
          :disabled="autoBusy || autoStatus !== 'ready' || loading"
          :title="translate('app_targets_auto_title', 'Automatically add new apps')"
          :summary="translate('app_targets_auto_desc', 'Add newly installed user apps in the background. Existing apps are not selected. Saved immediately.')"
          @update:model-value="setAutoTargets"
        >
          <template #start><MiuixIcon :icon="AddCircle" :size="23" /></template>
        </MiuixSwitchPreference>
        <div v-if="autoBusy || autoStatus === 'loading'" class="targets-auto-state" role="status">
          <MiuixProgressIndicator type="circular" :size="18" />
          {{ translate('home_status_loading', 'Checking') }}
        </div>
        <div v-if="autoError" class="targets-auto-state" role="alert">
          <span>{{ translate('app_targets_auto_error', 'Unable to update automatic selection. Check that the module is up to date.') }}</span>
          <MiuixButton v-if="autoStatus === 'error'" @click="loadAutoTargets">{{ translate('functional_button_retry', 'Retry') }}</MiuixButton>
        </div>
      </MiuixCard>
      <div v-if="initialLoading" class="targets-loading" role="status">
        <MiuixProgressIndicator type="circular" :size="34" />
        <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
      </div>

      <div v-else-if="targetEntries.length > 0" class="targets-list">
        <template v-for="(entry, index) in renderedTargetEntries" :key="entry.targetKey">
        <h3 v-if="showUserGroups && (index === 0 || renderedTargetEntries[index - 1]?.userId !== entry.userId)" class="targets-user-heading">
          {{ translate('app_target_user', 'User') }} {{ entry.userId }}<span v-if="entry.currentUser"> · {{ translate('app_target_current_user', 'Current') }}</span>
        </h3>
        <div class="target-app-row">
        <MiuixCheckboxPreference
          :model-value="entry.selected"
          :disabled="loading || selectingRecommended"
          :title="entry.appName"
          :summary="entry.packageName"
          location="end"
          @update:model-value="setSelected(entry, $event)"
        >
          <template #start>
            <span class="app-icon-frame" :class="`app-icon-frame--${iconState(entry.packageName)}`">
              <img
                class="app-icon"
                :src="`ksu://icon/${entry.packageName}`"
                :alt="entry.appName"
                loading="lazy"
                decoding="async"
                draggable="false"
                @load="setIconState(entry.packageName, 'loaded')"
                @error="setIconState(entry.packageName, 'error')"
              >
              <MiuixIcon
                v-if="iconState(entry.packageName) !== 'loaded'"
                class="app-icon-fallback"
                :icon="All"
                :size="24"
              />
            </span>
          </template>
        </MiuixCheckboxPreference>
        <button
          type="button"
          class="target-app-settings"
          :aria-label="`${translate('soter_app_settings', 'App settings')}: ${entry.appName}`"
          :title="translate('soter_app_settings', 'App settings')"
          :disabled="loading || selectingRecommended"
          @click="openAppSettings(entry)"
        >
          <MiuixIcon :icon="More" :size="22" />
        </button>
        </div>
        </template>
        <div v-if="renderedTargetEntries.length < targetEntries.length" class="app-list-batch-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="24" />
          <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
        </div>
      </div>

      <div v-else class="targets-empty">
        <MiuixIcon :icon="All" :size="34" />
        <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
      </div>
      </div>
    </main>

    <MiuixFloatingActionButton
      v-show="!systemSheetOpen && !appSheetOpen"
      class="targets-apply"
      :disabled="loading || selectingRecommended || !applyEnabled"
      :aria-label="translate('functional_button_apply', 'Apply')"
      :title="translate('functional_button_apply', 'Apply')"
      @click="apply"
    >
      <MiuixProgressIndicator
        v-if="loading && !refreshing"
        type="circular"
        :size="27"
        :stroke-width="3"
      />
      <MiuixIcon v-else :icon="Ok" />
    </MiuixFloatingActionButton>

    <MiuixBottomSheet
      v-model="systemSheetOpen"
      :title="translate('add_system_app_title', 'Add System App')"
    >
      <template #start-action>
        <MiuixIconButton
          :aria-label="translate('functional_button_cancel', 'Cancel')"
          @click="closeSystemApps"
        >
          <MiuixIcon :icon="Close" />
        </MiuixIconButton>
      </template>
      <template #end-action>
        <MiuixButton type="primary" :disabled="loading" @click="saveSystemApps">
          {{ translate('functional_button_save', 'Save') }}
        </MiuixButton>
      </template>

      <div class="system-app-sheet">
        <MiuixSearchBar
          v-model="systemSearchQuery"
          :label="translate('search_bar_search_placeholder', 'Search')"
          :cancel-text="translate('functional_button_cancel', 'Cancel')"
        />

        <div v-if="initialLoading" class="system-app-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="32" />
        </div>

        <div v-else-if="systemEntries.length > 0" class="system-app-list">
          <template v-for="(entry, index) in renderedSystemEntries" :key="entry.targetKey">
          <h3 v-if="showUserGroups && (index === 0 || renderedSystemEntries[index - 1]?.userId !== entry.userId)" class="targets-user-heading">
            {{ translate('app_target_user', 'User') }} {{ entry.userId }}<span v-if="entry.currentUser"> · {{ translate('app_target_current_user', 'Current') }}</span>
          </h3>
          <div class="target-app-row">
          <MiuixCheckboxPreference
            :model-value="systemSelection.has(entry.targetKey) || systemSelection.has(entry.packageName)"
            :disabled="loading"
            :title="entry.appName"
            :summary="entry.packageName"
            location="end"
            @update:model-value="setSystemSelected(entry.targetKey, $event)"
          >
            <template #start>
              <span class="app-icon-frame" :class="`app-icon-frame--${iconState(entry.packageName)}`">
                <img
                  class="app-icon"
                  :src="`ksu://icon/${entry.packageName}`"
                  :alt="entry.appName"
                  loading="lazy"
                  decoding="async"
                  draggable="false"
                  @load="setIconState(entry.packageName, 'loaded')"
                  @error="setIconState(entry.packageName, 'error')"
                >
                <MiuixIcon
                  v-if="iconState(entry.packageName) !== 'loaded'"
                  class="app-icon-fallback"
                  :icon="All"
                  :size="24"
                />
              </span>
            </template>
          </MiuixCheckboxPreference>
          <button
            type="button"
            class="target-app-settings"
            :aria-label="`${translate('soter_app_settings', 'App settings')}: ${entry.appName}`"
            :title="translate('soter_app_settings', 'App settings')"
            :disabled="loading"
            @click="openAppSettings(entry)"
          >
            <MiuixIcon :icon="More" :size="22" />
          </button>
          </div>
          </template>
          <div v-if="renderedSystemEntries.length < systemEntries.length" class="app-list-batch-loading" role="status">
            <MiuixProgressIndicator type="circular" :size="24" />
            <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
          </div>
        </div>

        <div v-else class="targets-empty targets-empty--sheet">
          <MiuixIcon :icon="All" :size="32" />
          <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
        </div>
      </div>
    </MiuixBottomSheet>

    <MiuixBottomSheet
      v-if="appSettingsEntry"
      :model-value="appSheetOpen"
      :title="appSettingsEntry.appName"
      :close-on-click-modal="!appSettingsBusy"
      @update:model-value="value => { if (!value) closeAppSettings() }"
    >
      <template #start-action>
        <MiuixIconButton
          :disabled="appSettingsBusy"
          :aria-label="translate('functional_button_cancel', 'Close')"
          @click="closeAppSettings"
        ><MiuixIcon :icon="Close" /></MiuixIconButton>
      </template>
      <div class="target-app-sheet" :aria-busy="appSettingsStatus === 'loading' || appSettingsBusy">
        <p class="target-app-identity">{{ appSettingsEntry.packageName }}</p>
        <p class="target-app-profile">{{ translate('app_target_user', 'User') }} {{ appSettingsEntry.userId }}</p>
        <div v-if="appSettingsStatus === 'loading'" class="target-app-pending" role="status">
          <MiuixProgressIndicator type="circular" :size="28" />
          <span>{{ translate('home_status_loading', 'Checking') }}</span>
        </div>
        <template v-else-if="appSettingsStatus === 'ready'">
          <MiuixSwitchPreference
            :model-value="appSoterSelected"
            :title="translate('soter_app_enabled', 'Take over remote SOTER')"
            :summary="translate('soter_app_enabled_desc', 'Only this app in this Android user is opted in. Independent of normal OMK selection; saved immediately.')"
            :disabled="appSettingsBusy || isDev()"
            @update:model-value="setAppSoter"
          />
          <p class="target-app-note">
            {{ translate('soter_app_original', 'In per-app mode, apps not opted in continue using the original SOTER service.') }}
          </p>
          <p v-if="!appSoterReady" class="target-app-note target-app-note--warning" role="status">
            {{ translate('soter_app_inactive', 'Remote SOTER is not active: enable per-app takeover and the remote relay in SOTER settings.') }}
          </p>
          <div v-if="appSettingsBusy" class="target-app-pending" role="status">
            <MiuixProgressIndicator type="circular" :size="22" />
          </div>
        </template>
        <p v-if="appSettingsError" class="target-app-error" role="alert">{{ appSettingsError }}</p>
        <MiuixButton v-if="appSettingsStatus === 'error'" @click="loadAppSettings">
          {{ translate('functional_button_retry', 'Retry') }}
        </MiuixButton>
        <p v-if="isDev()" class="target-app-note">{{ translate('soter_hal_preview', 'Preview only. Device settings cannot be saved here.') }}</p>
      </div>
    </MiuixBottomSheet>
  </section>
</template>

<style scoped>
.targets-view {
  position: relative;
  box-sizing: border-box;
  min-height: 100%;
  color: var(--m-color-on-background);
  background: var(--m-color-surface);
}

.targets-top-bar {
  position: sticky;
  z-index: 40;
  top: 0;
  box-sizing: border-box;
  padding-top: calc(var(--omk-top-inset) / var(--omk-ui-scale));
  /* Keep a solid fallback for older Android WebViews that do not implement
     CSS color-mix; the translucent value is then layered on when supported. */
  background: var(--m-color-surface);
  background: color-mix(in srgb, var(--m-color-surface) 92%, transparent);
  backdrop-filter: blur(18px) saturate(1.25);
}

.targets-top-bar :deep(.m-top-app-bar__nav) {
  padding-inline-start: 8px;
  padding-inline-end: 0;
}

.targets-top-bar :deep(.m-top-app-bar__actions) {
  padding-inline-start: 0;
  padding-inline-end: 8px;
}

.targets-menu {
  position: relative;
}

.targets-menu-scrim {
  position: fixed;
  z-index: 35;
  inset: 0;
}

.targets-menu-toggle {
  position: relative;
  z-index: 41;
}

.targets-menu-popup {
  position: absolute;
  z-index: 50;
  top: calc(100% + 6px);
  inset-inline-end: 0;
  box-sizing: border-box;
  width: min(296px, calc(100vw - 24px));
  min-width: min(296px, calc(100vw - 24px));
  max-height: calc(100vh - 116px);
  max-height: calc(100dvh - 116px);
  overflow-y: auto;
  padding: 6px;
  border: 1px solid color-mix(in srgb, var(--m-color-on-surface) 7%, transparent);
  border-radius: 20px;
  background: var(--m-color-surface-container);
  background: color-mix(in srgb, var(--m-color-surface-container) 96%, transparent);
  box-shadow: 0 14px 36px rgb(0 0 0 / 18%), 0 3px 10px rgb(0 0 0 / 9%);
  backdrop-filter: blur(22px) saturate(1.15);
  scrollbar-width: none;
  -ms-overflow-style: none;
}

.targets-menu-popup::-webkit-scrollbar {
  display: none;
}

.targets-menu-popup :deep(.m-card) {
  gap: 0;
  padding: 0;
  border-radius: inherit;
  background: transparent;
}

.targets-menu-popup :deep(.m-button) {
  width: 100%;
  min-height: 48px;
  justify-content: flex-start;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 16px;
  background: transparent;
  color: var(--m-color-on-surface);
  font-size: 17px;
  font-weight: 400;
  line-height: 1.25;
  white-space: normal;
  text-align: start;
}

.targets-menu-label {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.targets-menu-label small {
  color: var(--m-color-on-surface-variant-summary);
  font-size: 13px;
  font-weight: 400;
  line-height: 1.4;
}

.targets-menu-popup :deep(.m-button:hover),
.targets-menu-popup :deep(.m-button:focus-visible) {
  background: color-mix(in srgb, var(--m-color-on-surface) 7%, transparent);
}

.targets-menu-popup :deep(.m-button::after) {
  display: none;
}

.targets-menu-popup :deep(.m-button:active) {
  background: color-mix(in srgb, var(--m-color-primary) 12%, transparent);
}

.targets-menu-popup :deep(.m-button .m-icon) {
  flex: none;
  color: var(--m-color-on-surface);
}

.targets-menu-enter-active,
.targets-menu-leave-active {
  transition: opacity 140ms ease, transform 180ms cubic-bezier(.2, .8, .2, 1);
  transform-origin: top right;
}

[dir='rtl'] .targets-menu-enter-active,
[dir='rtl'] .targets-menu-leave-active {
  transform-origin: top left;
}

.targets-menu-enter-from,
.targets-menu-leave-to {
  opacity: 0;
  transform: translateY(-5px) scale(.97);
}

.targets-content {
  position: relative;
  /* Clip translated content without creating a nested scroll container. */
  contain: paint;
  box-sizing: border-box;
  width: min(100%, 680px);
  min-height: 240px;
  /* Room for the maximum pull, without increasing the resting scroll extent. */
  margin: 0 auto -48px;
  padding: 8px 12px calc(144px + var(--omk-bottom-inset) / var(--omk-ui-scale));
}

.targets-pull {
  position: absolute;
  top: 8px;
  inset-inline: 12px;
  height: 64px;
  pointer-events: none;
  opacity: 0;
  transform: translate3d(0, -64px, 0);
  color: var(--m-color-on-surface-variant-summary);
  font-size: 14px;
  font-weight: 500;
  transition: transform 220ms cubic-bezier(.2, .8, .2, 1), opacity 180ms ease;
}

.targets-pull-body {
  transform: translate3d(0, 0, 0);
  transition: transform 220ms cubic-bezier(.2, .8, .2, 1);
}

.targets-pull-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 100%;
}

.targets-pull-capsule {
  position: relative;
  box-sizing: border-box;
  width: 22px;
  height: 22px;
  flex: none;
  transition: transform 220ms cubic-bezier(.2, .8, .2, 1);
}

/* Translate the round caps and stretch only the straight sides so the outline
   stays 2px thick even at maximum pull. None of these updates change layout. */
.targets-pull-capsule::before,
.targets-pull-capsule::after,
.targets-pull-stem {
  position: absolute;
  box-sizing: border-box;
  inset-inline: 0;
  border: 2px solid currentColor;
  transition: inherit;
}

.targets-pull-capsule::before {
  content: '';
  top: 0;
  height: 11px;
  border-bottom: 0;
  border-radius: 11px 11px 0 0;
  transform: translate3d(0, calc(var(--pull-stretch, 0) * -1px), 0);
}

.targets-pull-capsule::after {
  content: '';
  top: 11px;
  height: 11px;
  border-top: 0;
  border-radius: 0 0 11px 11px;
}

.targets-pull-stem {
  top: 10px;
  height: 1px;
  border-block: 0;
  transform-origin: center bottom;
  transform: scaleY(calc(var(--pull-stretch, 0) + 1));
}

.targets-pull--refreshing { color: var(--m-color-primary); }

@media (prefers-reduced-motion: reduce) {
  .targets-pull, .targets-pull-body, .targets-pull-capsule { transition: none; }
}

.targets-auto { margin-bottom: 16px; }
.targets-auto-state { display: flex; align-items: center; gap: 10px; padding: 0 16px 14px; font-size: 13px; color: var(--m-color-on-surface-variant-summary); }
.targets-auto-state[role='alert'] { color: var(--m-color-error); }
.targets-user-heading { margin: 8px 12px 0; color: var(--m-color-on-surface-variant-summary); font-size: 14px; font-weight: 500; }

.targets-list,
.system-app-list {
  width: 100%;
  display: grid;
  gap: 12px;
}

.targets-list :deep(.m-basic-component),
.system-app-list :deep(.m-basic-component) {
  min-height: 74px;
  padding: 12px 14px;
  border-radius: 22px;
  overflow: hidden;
  background: var(--m-color-surface-container);
}

.target-app-row {
  display: flex;
  align-items: stretch;
  min-width: 0;
  border-radius: 22px;
  overflow: hidden;
  background: var(--m-color-surface-container);
}

.target-app-row :deep(.m-basic-component) {
  flex: 1;
  min-width: 0;
  padding-inline-end: 4px;
  border-radius: 0;
  background: transparent;
}

.target-app-settings {
  display: grid;
  place-items: center;
  flex: none;
  width: 44px;
  min-height: 48px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--m-color-on-surface-variant-summary);
  cursor: pointer;
  -webkit-tap-highlight-color: transparent;
}

.target-app-settings:active { background: color-mix(in srgb, var(--m-color-primary) 10%, transparent); }
.target-app-settings:focus-visible { outline: 2px solid var(--m-color-primary); outline-offset: -4px; }
.target-app-settings:disabled { opacity: .45; cursor: default; }
.target-app-sheet { padding: 0 4px 22px; }
.target-app-identity { margin: 0; overflow-wrap: anywhere; color: var(--m-color-on-surface-variant-summary); font-size: 14px; }
.target-app-profile { margin: 6px 0 16px; color: var(--m-color-on-surface-variant-summary); font-size: 13px; }
.target-app-note, .target-app-error { margin: 14px 0; font-size: 14px; line-height: 1.55; color: var(--m-color-on-surface-variant-summary); }
.target-app-note--warning { color: var(--m-color-primary); }
.target-app-error { color: var(--m-color-error); }
.target-app-pending { display: flex; align-items: center; justify-content: center; gap: 12px; min-height: 64px; }

.targets-list :deep(.m-basic-component__row),
.system-app-list :deep(.m-basic-component__row) {
  gap: 12px;
}

.targets-list :deep(.m-basic-component__center),
.system-app-list :deep(.m-basic-component__center) {
  overflow: hidden;
}

.targets-list :deep(.m-basic-component__center > *),
.system-app-list :deep(.m-basic-component__center > *) {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}


.app-icon-frame {
  position: relative;
  box-sizing: border-box;
  display: inline-flex;
  flex: none;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  overflow: hidden;
  border-radius: 50%;
  color: var(--m-color-on-tertiary-container);
  background: var(--m-color-tertiary-container);
}

.app-icon {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  opacity: 0;
}

.app-icon-frame--loaded { background: transparent; }

.app-icon-frame--loaded .app-icon {
  opacity: 1;
}

.app-icon-fallback {
  opacity: .8;
}

.app-list-batch-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 64px;
}

.targets-loading,
.system-app-loading,
.targets-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 220px;
  color: var(--m-color-on-surface-variant-summary);
}

.targets-empty {
  flex-direction: column;
  gap: 10px;
  text-align: center;
}

.targets-empty p {
  margin: 0;
  font-size: 15px;
}

.targets-apply {
  position: fixed;
  z-index: 30;
  right: calc(20px + var(--omk-right-inset) / var(--omk-ui-scale));
  bottom: calc(14px + var(--omk-bottom-inset) / var(--omk-ui-scale));
}

[dir='rtl'] .targets-apply {
  right: auto;
  left: calc(20px + var(--omk-left-inset) / var(--omk-ui-scale));
}

.system-app-sheet {
  box-sizing: border-box;
  min-height: min(65vh, 520px);
  /* The teleported MIUIX sheet already reserves the system gesture area. */
  padding-bottom: 18px;
}

.system-app-sheet > :deep(.m-search-bar) {
  position: sticky;
  z-index: 2;
  top: 0;
  padding: 2px 0 12px;
  background: var(--m-color-background);
}

.targets-empty--sheet {
  min-height: 180px;
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
  .targets-content {
    padding-inline: 10px;
  }

  .targets-list :deep(.m-basic-component),
  .system-app-list :deep(.m-basic-component) {
    padding-inline: 12px;
  }

  .system-app-sheet {
    min-height: 68vh;
  }
}

@media (prefers-reduced-motion: reduce) {
  .targets-menu-enter-active,
  .targets-menu-leave-active {
    transition: none;
  }
}
</style>

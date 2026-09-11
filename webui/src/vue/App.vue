<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import {
  MiuixDialog,
  MiuixIcon,
  MiuixButton,
  MiuixNavigationBar,
  MiuixProgressIndicator,
  MiuixSnackbarHost,
  MiuixSwitchPreference,
  showSnackbar,
  setThemeMode,
} from 'miuix-vue'
import { All, Settings, Tune } from 'miuix-vue/icons'
import { AppList, type AppListSnapshot } from '../app_list/app_list'
import { appearance } from '../appearance'
import { Cli, type ActivityEntry, type KeyboxRevocationStatus } from '../cli'
import { ConfigOhMyKeyMint } from '../config_ohmykeymint'
import { FileSelector } from '../file_selector/file_selector'
import { History } from '../history'
import { i18n } from '../i18n'
import { fetchLatestSecurityPatch } from '../security_patch'
import { isDev } from '../utils/dev'
import HomeView, { type KeyboxStatus, type ModuleStatus, type TeeStatus } from './HomeView.vue'
import PifFingerprintDialog from './PifFingerprintDialog.vue'
import SettingsView from './SettingsView.vue'
import TargetsView from './TargetsView.vue'
import ToolsView, { type ToolEvent } from './ToolsView.vue'
import FileBrowserSheet from './FileBrowserSheet.vue'
import './app.scss'

const cli = new Cli()
const config = new ConfigOhMyKeyMint(cli)
const appList = new AppList(config)
const fileSelector = new FileSelector()
const history = new History()

const pageIndex = ref(0)
const targetsOpen = ref(false)
const targetsLoading = ref(false)
const snapshot = ref<AppListSnapshot>(appList.getSnapshot())
const moduleStatus = ref<ModuleStatus>('loading')
const keyboxStatus = ref<KeyboxStatus>('loading')
const keyboxSource = ref<'google_hardware' | 'google_remote' | 'unknown'>('unknown')
const keyboxLevel = ref<'tee' | 'strongbox' | 'unknown'>('unknown')
const keyboxRevocation = ref<KeyboxRevocationStatus>('not_checked')
const teeStatus = ref<TeeStatus>('loading')
const securityPatch = ref<string | null>(null)
const spoofedDevice = ref<string | null | undefined>(undefined)
const activities = ref<ActivityEntry[]>([])
const activityStatus = ref<'loading' | 'ready' | 'error'>('loading')
const activityClearBusy = ref(false)
const securityPatchBusy = ref<'sync' | 'restore' | null>(null)
const adbBusy = ref(false)
const adbOpen = ref(false)
const adbEnabled = ref(true)
const adbDevOptions = ref(true)
const adbUsbDebug = ref(true)
const adbOemUnlock = ref(true)
const pifOpen = ref(false)
const keyboxOpen = ref(false)
const selectedKeybox = ref<{ name: string, contents: Uint8Array } | null>(null)
const keyboxBusy = ref(false)
const targetsView = ref<InstanceType<typeof TargetsView> | null>(null)
const pifDialog = ref<InstanceType<typeof PifFingerprintDialog> | null>(null)

const pageIds = ['home', 'tools', 'settings'] as const
const navItems = computed(() => [
  { label: i18n.t('nav_home') === 'nav_home' ? 'Home' : i18n.t('nav_home') },
  { label: i18n.t('nav_tools') === 'nav_tools' ? 'Tools' : i18n.t('nav_tools') },
  { label: i18n.t('nav_settings') === 'nav_settings' ? 'Settings' : i18n.t('nav_settings') },
])

let unsubscribeAppList: (() => void) | null = null
let unsubscribeFileSelector: (() => void) | null = null
let unsubscribeAppearance: (() => void) | null = null
let keydownListener: ((event: KeyboardEvent) => void) | null = null
let pageHistoryActive = false
const overlayHistory = new Set<string>()
let targetsRefreshTimer: number | null = null
let navigationElement: HTMLElement | null = null
let navigationPointerId: number | null = null
let navigationPointerStartX = 0
let navigationPointerStartIndex = 0
let navigationPointerSlotWidth = 1
let navigationWasDragged = false
let navigationSuppressClick = false

function liquidNavigationEnabled(): boolean {
  const root = document.documentElement
  return root.dataset.floatingBottomBar === 'true' && root.dataset.liquidGlass === 'true'
}

function clampNavigationIndex(index: number): number {
  return Math.max(0, Math.min(pageIds.length - 1, index))
}

function navigationPosition(clientX: number): number {
  if (!navigationElement) return pageIndex.value
  const bounds = navigationElement.getBoundingClientRect()
  const slot = Math.max(1, (bounds.width - 8) / pageIds.length)
  return clampNavigationIndex((clientX - bounds.left - 4) / slot)
}

function onNavigationPointerDown(event: PointerEvent): void {
  if (!navigationElement || !liquidNavigationEnabled() || !event.isPrimary || event.button !== 0
      || navigationPointerId !== null) return
  const bounds = navigationElement.getBoundingClientRect()
  navigationPointerSlotWidth = Math.max(
    1,
    (bounds.width - 8) / pageIds.length,
  )
  navigationPointerId = event.pointerId
  navigationPointerStartX = event.clientX
  navigationPointerStartIndex = Math.floor(navigationPosition(event.clientX))
  navigationWasDragged = false
  navigationElement.classList.add('is-pressing')
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(navigationPointerStartIndex))
  navigationElement.style.setProperty('--omk-liquid-nav-scale', '1.392857')
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', '0px')
  navigationElement.style.setProperty(
    '--omk-liquid-nav-highlight-x',
    `${event.clientX - bounds.left}px`,
  )
  try { navigationElement.setPointerCapture(event.pointerId) } catch { /* WebView may reject capture. */ }
  event.preventDefault()
}

function onNavigationPointerMove(event: PointerEvent): void {
  if (!navigationElement || navigationPointerId !== event.pointerId) return
  if (Math.abs(event.clientX - navigationPointerStartX) > 1) {
    navigationElement.classList.add('is-dragging')
    navigationWasDragged = true
  }
  const position = navigationPointerStartIndex
    + (event.clientX - navigationPointerStartX) / navigationPointerSlotWidth
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(clampNavigationIndex(position)))
  const bounds = navigationElement.getBoundingClientRect()
  const distance = event.clientX - navigationPointerStartX
  const fraction = Math.min(1, Math.abs(distance) / Math.max(1, bounds.width))
  const rubberBand = Math.sign(distance) * 4 * (1 - (1 - fraction) ** 2)
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', `${rubberBand}px`)
  navigationElement.style.setProperty(
    '--omk-liquid-nav-highlight-x',
    `${event.clientX - bounds.left}px`,
  )
  event.preventDefault()
}

function onNavigationPointerUp(event: PointerEvent): void {
  if (!navigationElement || navigationPointerId !== event.pointerId) return
  const target = Math.round(navigationPosition(event.clientX))
  navigationSuppressClick = navigationWasDragged
  navigationPointerId = null
  navigationWasDragged = false
  navigationElement.classList.remove('is-pressing', 'is-dragging')
  navigationElement.style.setProperty('--omk-liquid-nav-scale', '1')
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', '0px')
  navigationElement.style.setProperty('--omk-liquid-nav-highlight-x', '50%')
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(target))
  try { navigationElement.releasePointerCapture(event.pointerId) } catch { /* Already released. */ }
  if (target !== pageIndex.value) setPage(target)
  window.setTimeout(() => { navigationSuppressClick = false }, 120)
  event.preventDefault()
}

function onNavigationClickCapture(event: Event): void {
  if (!navigationSuppressClick) return
  navigationSuppressClick = false
  event.preventDefault()
  event.stopImmediatePropagation()
}

function onNavigationPointerCancel(event: PointerEvent): void {
  if (!navigationElement || navigationPointerId !== event.pointerId) return
  navigationPointerId = null
  navigationWasDragged = false
  navigationSuppressClick = false
  navigationElement.classList.remove('is-pressing', 'is-dragging')
  navigationElement.style.setProperty('--omk-liquid-nav-scale', '1')
  navigationElement.style.setProperty('--omk-liquid-nav-panel-offset', '0px')
  navigationElement.style.setProperty('--omk-liquid-nav-highlight-x', '50%')
  navigationElement.style.setProperty('--omk-liquid-nav-index', String(pageIndex.value))
}

function notify(message: string, error = false): void {
  void showSnackbar({ message, duration: error ? 6000 : 'long', withDismissAction: true })
}

function setPage(index: number): void {
  if (index < 0 || index >= pageIds.length || index === pageIndex.value) return
  pageIndex.value = index
  if (index !== 0 && !pageHistoryActive) {
    pageHistoryActive = true
    history.push('main-page', () => {
      pageHistoryActive = false
      pageIndex.value = 0
    })
  } else if (index === 0 && pageHistoryActive) {
    pageHistoryActive = false
    history.consume('main-page')
  }
  window.scrollTo(0, 0)
}

function openTargets(): void {
  if (targetsOpen.value) return
  targetsOpen.value = true
  history.push('app-targets', () => { targetsOpen.value = false })
  window.setTimeout(() => { if (targetsOpen.value) void reloadApps(false) }, 220)
}

function closeTargets(): void {
  if (!targetsOpen.value) return
  targetsOpen.value = false
  if (targetsRefreshTimer !== null) {
    window.clearTimeout(targetsRefreshTimer)
    targetsRefreshTimer = null
  }
  history.consume('app-targets')
}

// Package installation happens outside the WebUI.  Refresh when Android
// brings the WebView back to the foreground so a newly installed app appears
// without requiring the user to close and reopen the selector.  The short
// debounce lets the overlay/focus animation paint before crossing the
// synchronous KernelSU package bridge.
function scheduleTargetsRefresh(): void {
  if (!targetsOpen.value
      || document.visibilityState !== 'visible'
      || targetsLoading.value
      || targetsRefreshTimer !== null) return
  targetsRefreshTimer = window.setTimeout(() => {
    targetsRefreshTimer = null
    if (targetsOpen.value && document.visibilityState === 'visible' && !targetsLoading.value) {
      void reloadApps(false)
    }
  }, 180)
}

function refreshTargetsWhenForegrounded(): void {
  if (document.visibilityState === 'visible') scheduleTargetsRefresh()
}

function onTargetsOverlayOpen(): void {
  const key = 'targets-overlay'
  if (overlayHistory.has(key)) return
  overlayHistory.add(key)
  history.push(key, () => { targetsView.value?.dismissOverlay() })
}

function onTargetsOverlayClose(): void {
  const key = 'targets-overlay'
  if (overlayHistory.delete(key)) history.consume(key)
}

function handleEscape(): void {
  if (targetsOpen.value && targetsView.value?.dismissOverlay()) return
  if (history.size > 0) history.back()
}

async function reloadApps(readConfig: boolean): Promise<void> {
  targetsLoading.value = true
  try {
    if (readConfig) await config.read()
    await appList.fetch()
    appList.syncSystemAppsWithConfig()
    snapshot.value = appList.getSnapshot()
    moduleStatus.value = config.isWritable ? 'ready' : 'error'
  } catch (error) {
    moduleStatus.value = 'error'
    console.error('Unable to load OMK configuration:', error)
    notify(i18n.t('prompt_load_error'), true)
  } finally {
    targetsLoading.value = false
  }
}

async function saveTargets(): Promise<void> {
  targetsLoading.value = true
  try {
    await appList.save()
    snapshot.value = appList.getSnapshot()
    notify(i18n.t('prompt_saved_target'))
    closeTargets()
  } catch (error) {
    console.error('Unable to save OMK targets:', error)
    notify(i18n.t('prompt_save_error'), true)
  } finally {
    targetsLoading.value = false
  }
}

async function refreshIdentity(force = false): Promise<void> {
  // The refresh path always queries the current backend state; keep the
  // parameter for callers that request an explicit refresh after a mutation.
  void force
  if (isDev()) {
    keyboxStatus.value = 'custom'
    keyboxSource.value = 'google_remote'
    keyboxLevel.value = 'tee'
    keyboxRevocation.value = 'not_listed'
    teeStatus.value = 'normal'
    securityPatch.value = '2026-08-01'
    spoofedDevice.value = 'Google Pixel 9 Pro'
    return
  }
  try {
    const [keybox, patch, tee, pif] = await Promise.allSettled([
      cli.getKeyboxState(),
      cli.getSystemSecurityPatch(),
      cli.getTeeStatus(),
      cli.getPifFingerprintState(),
    ])
    if (keybox.status === 'fulfilled') {
      const value = keybox.value
      keyboxStatus.value = value.valid ? (value.bundled ? 'bundled' : 'custom') : 'invalid'
      keyboxSource.value = value.source
      keyboxLevel.value = value.level
      keyboxRevocation.value = value.valid ? 'checking' : value.revocation
      if (value.valid) {
        try { keyboxRevocation.value = await cli.checkKeyboxRevocation() }
        catch { keyboxRevocation.value = 'unknown' }
      }
    } else keyboxStatus.value = 'error'
    if (patch.status === 'fulfilled') securityPatch.value = patch.value
    if (tee.status === 'fulfilled') teeStatus.value = 'normal'
    else teeStatus.value = 'error'
    if (pif.status === 'fulfilled') {
      spoofedDevice.value = pif.value.enabled
        ? (/^google\s/i.test(pif.value.model) ? pif.value.model : `Google ${pif.value.model}`)
        : null
    }
  } catch (error) {
    console.error('Unable to load OMK identity:', error)
  }
}

async function refreshActivity(): Promise<void> {
  try {
    activities.value = (await cli.getActivityLog()).slice().sort((left, right) => right.timestamp - left.timestamp)
    activityStatus.value = 'ready'
  } catch (error) {
    if (isDev()) {
      const now = Math.floor(Date.now() / 1000)
      activities.value = [{ action: 'keybox_changed', detail: '', timestamp: now - 3600 }]
      activityStatus.value = 'ready'
    } else {
      activityStatus.value = 'error'
      console.error('Unable to load activity:', error)
    }
  }
}

async function chooseKeybox(): Promise<void> {
  try {
    const selected = await fileSelector.getSystemFileContent('xml')
    if (selected) {
      selectedKeybox.value = selected
      keyboxOpen.value = true
    }
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  }
}

async function installKeybox(): Promise<void> {
  const selected = selectedKeybox.value
  if (!selected || keyboxBusy.value) return
  keyboxBusy.value = true
  try {
    if (!isDev()) await cli.installKeybox(selected.contents)
    notify(i18n.t('prompt_keybox_replaced'))
    keyboxOpen.value = false
    selectedKeybox.value = null
    await Promise.all([refreshIdentity(true), refreshActivity()])
  } catch (error) {
    notify(i18n.t('prompt_keybox_replace_error', error instanceof Error ? error.message : String(error)), true)
  } finally {
    keyboxBusy.value = false
  }
}

async function syncPatch(restore: boolean): Promise<void> {
  if (securityPatchBusy.value !== null) return
  securityPatchBusy.value = restore ? 'restore' : 'sync'
  try {
    if (restore) {
      if (!isDev()) await cli.restoreDefaultSecurityPatch()
      await refreshIdentity(true)
      notify(i18n.t('prompt_security_patch_restored_default'))
    } else {
      const date = await fetchLatestSecurityPatch(() => cli.fetchSecurityBulletin())
      const applied = isDev() ? date : await cli.syncSecurityPatch(date)
      securityPatch.value = applied
      notify(i18n.t('prompt_security_patch_sync_complete', applied))
    }
    await refreshActivity()
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  } finally {
    securityPatchBusy.value = null
  }
}

async function applyAdbDisabler(): Promise<void> {
  if (adbBusy.value) return
  adbBusy.value = true
  try {
    if (!isDev()) {
      await cli.setAdbDisabler(
        adbEnabled.value,
        adbDevOptions.value,
        adbUsbDebug.value,
        adbOemUnlock.value,
      )
    }
    adbOpen.value = false
    notify(i18n.t('prompt_adb_disabler_applied'))
    await refreshActivity()
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  } finally {
    adbBusy.value = false
  }
}

function onTool(event: ToolEvent): void {
  switch (event) {
    case 'openAppTargets': openTargets(); break
    case 'installKeybox': void chooseKeybox(); break
    case 'syncSecurityPatch': void syncPatch(false); break
    case 'restoreSecurityPatch': void syncPatch(true); break
    case 'openAdbDisabler': void openAdbDisabler(); break
    case 'spoofPif': pifOpen.value = true; break
  }
}

async function openAdbDisabler(): Promise<void> {
  if (adbOpen.value) return
  adbOpen.value = true
  if (isDev()) {
    adbEnabled.value = false
    adbDevOptions.value = true
    adbUsbDebug.value = true
    adbOemUnlock.value = true
    return
  }
  try {
    const state = await cli.getAdbDisabler()
    adbEnabled.value = state.enabled
    adbDevOptions.value = state.dev_options
    adbUsbDebug.value = state.usb_debug
    adbOemUnlock.value = state.oem_unlock
  } catch (error) {
    adbOpen.value = false
    notify(error instanceof Error ? error.message : String(error), true)
  }
}

async function clearActivities(): Promise<void> {
  if (activityClearBusy.value) return
  activityClearBusy.value = true
  try {
    if (!isDev()) await cli.clearActivityLog()
    activities.value = []
    notify(i18n.t('home_activity_cleared'))
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), true)
  } finally {
    activityClearBusy.value = false
  }
}

onMounted(async () => {
  const applyMiuixTheme = (): void => {
    const mode = appearance.mode === 'auto' ? 'system' : appearance.mode === 'amoled' ? 'dark' : appearance.mode
    setThemeMode(mode)
  }
  applyMiuixTheme()
  navigationElement = document.querySelector<HTMLElement>('.main-navigation')
  navigationElement?.style.setProperty('--omk-liquid-nav-index', String(pageIndex.value))
  navigationElement?.style.setProperty('--omk-liquid-nav-scale', '1')
  navigationElement?.addEventListener('pointerdown', onNavigationPointerDown)
  navigationElement?.addEventListener('pointermove', onNavigationPointerMove)
  navigationElement?.addEventListener('pointerup', onNavigationPointerUp)
  navigationElement?.addEventListener('pointercancel', onNavigationPointerCancel)
  navigationElement?.addEventListener('click', onNavigationClickCapture, true)
  unsubscribeAppearance = appearance.onChange(applyMiuixTheme)
  keydownListener = event => {
    if (event.key === 'Escape') {
      event.preventDefault()
      handleEscape()
    }
  }
  window.addEventListener('keydown', keydownListener)
  document.addEventListener('visibilitychange', refreshTargetsWhenForegrounded)
  window.addEventListener('focus', refreshTargetsWhenForegrounded)
  unsubscribeAppList = appList.subscribe(value => { snapshot.value = value })
  unsubscribeFileSelector = fileSelector.subscribe(() => {
    if (fileSelector.open && !overlayHistory.has('file-selector')) {
      overlayHistory.add('file-selector')
      history.push('file-selector', () => fileSelector.cancel())
    } else if (!fileSelector.open && overlayHistory.delete('file-selector')) {
      history.consume('file-selector')
    }
  })
  await Promise.all([reloadApps(true), refreshIdentity(), refreshActivity()])
})

onBeforeUnmount(() => {
  if (targetsRefreshTimer !== null) {
    window.clearTimeout(targetsRefreshTimer)
    targetsRefreshTimer = null
  }
  document.removeEventListener('visibilitychange', refreshTargetsWhenForegrounded)
  window.removeEventListener('focus', refreshTargetsWhenForegrounded)
  if (keydownListener !== null) window.removeEventListener('keydown', keydownListener)
  navigationElement?.removeEventListener('pointerdown', onNavigationPointerDown)
  navigationElement?.removeEventListener('pointermove', onNavigationPointerMove)
  navigationElement?.removeEventListener('pointerup', onNavigationPointerUp)
  navigationElement?.removeEventListener('pointercancel', onNavigationPointerCancel)
  navigationElement?.removeEventListener('click', onNavigationClickCapture, true)
  navigationElement = null
  unsubscribeAppList?.()
  unsubscribeFileSelector?.()
  unsubscribeAppearance?.()
  history.destroy()
})

watch(pageIndex, index => {
  if (navigationPointerId === null) {
    navigationElement?.style.setProperty('--omk-liquid-nav-index', String(index))
  }
})

watch(pifOpen, open => {
  if (open && !overlayHistory.has('pif-fingerprint')) {
    overlayHistory.add('pif-fingerprint')
    history.push('pif-fingerprint', () => {
      overlayHistory.delete('pif-fingerprint')
      pifDialog.value?.requestClose()
    })
  } else if (!open && overlayHistory.delete('pif-fingerprint')) history.consume('pif-fingerprint')
})
watch(adbOpen, open => {
  if (open && !overlayHistory.has('adb-disabler')) {
    overlayHistory.add('adb-disabler')
    history.push('adb-disabler', () => { if (!adbBusy.value) adbOpen.value = false })
  } else if (!open && overlayHistory.delete('adb-disabler')) history.consume('adb-disabler')
})
watch(keyboxOpen, open => {
  if (open && !overlayHistory.has('keybox')) {
    overlayHistory.add('keybox')
    history.push('keybox', () => { if (!keyboxBusy.value) keyboxOpen.value = false })
  } else if (!open && overlayHistory.delete('keybox')) history.consume('keybox')
})
</script>

<template>
  <div class="omk-app">
    <main v-show="!targetsOpen" class="page-host">
      <HomeView
        v-show="pageIndex === 0"
        :keybox-status="keyboxStatus"
        :keybox-source="keyboxSource"
        :keybox-level="keyboxLevel"
        :keybox-revocation="keyboxRevocation"
        :tee-status="teeStatus"
        :security-patch="securityPatch"
        :spoofed-device="spoofedDevice"
        :activities="activities"
        :activity-status="activityStatus"
        :activity-clear-busy="activityClearBusy"
        @clear-activities="clearActivities"
      />
      <ToolsView
        v-show="pageIndex === 1"
        :security-patch-busy="securityPatchBusy"
        :adb-busy="adbBusy"
        @open-app-targets="onTool('openAppTargets')"
        @install-keybox="onTool('installKeybox')"
        @sync-security-patch="onTool('syncSecurityPatch')"
        @restore-security-patch="onTool('restoreSecurityPatch')"
        @open-adb-disabler="onTool('openAdbDisabler')"
        @spoof-pif="onTool('spoofPif')"
      />
      <SettingsView v-show="pageIndex === 2" />
    </main>

    <MiuixNavigationBar
      v-show="!targetsOpen"
      :model-value="pageIndex"
      :items="navItems"
      :data-active-index="pageIndex"
      class="main-navigation"
      @update:model-value="setPage"
    >
      <template #icon="{ index }">
        <MiuixIcon :icon="index === 0 ? All : index === 1 ? Tune : Settings" :size="24" />
      </template>
    </MiuixNavigationBar>

    <TargetsView
      v-if="targetsOpen"
      ref="targetsView"
      :app-list="appList"
      :loading="targetsLoading"
      :apply-enabled="snapshot.isWritable"
      @close="closeTargets"
      @refresh="reloadApps(false)"
      @apply="saveTargets"
      @overlay-open="onTargetsOverlayOpen"
      @overlay-close="onTargetsOverlayClose"
    />

    <FileBrowserSheet :selector="fileSelector" />

    <MiuixDialog
      v-model="keyboxOpen"
      :title="i18n.t('replace_keybox_title')"
      :close-on-click-modal="!keyboxBusy"
    >
      <template #default="{ close }">
        <div class="confirm-sheet">
          <p>{{ selectedKeybox ? i18n.t('replace_keybox_selected_file', selectedKeybox.name) : '' }}</p>
          <div class="confirm-actions">
            <MiuixButton :disabled="keyboxBusy" @click="close">
              {{ i18n.t('functional_button_cancel') }}
            </MiuixButton>
            <MiuixButton type="primary" :disabled="keyboxBusy" @click="installKeybox">
              <MiuixProgressIndicator v-if="keyboxBusy" type="circular" :size="18" />
              {{ i18n.t('functional_button_replace') }}
            </MiuixButton>
          </div>
        </div>
      </template>
    </MiuixDialog>

    <MiuixDialog
      v-model="adbOpen"
      :title="i18n.t('tools_adb_disabler')"
      :close-on-click-modal="!adbBusy"
    >
      <template #default="{ close }">
        <div class="confirm-sheet adb-disabler-sheet">
          <p>{{ i18n.t('adb_disabler_desc') }}</p>
          <MiuixSwitchPreference
            v-model="adbEnabled"
            :title="i18n.t('adb_disabler_enabled')"
            :summary="i18n.t('adb_disabler_enabled_desc')"
            :disabled="adbBusy"
          />
          <MiuixSwitchPreference
            v-model="adbDevOptions"
            :title="i18n.t('adb_disabler_dev_options')"
            :summary="i18n.t('adb_disabler_dev_options_desc')"
            :disabled="adbBusy || !adbEnabled"
          />
          <MiuixSwitchPreference
            v-model="adbUsbDebug"
            :title="i18n.t('adb_disabler_usb_debug')"
            :summary="i18n.t('adb_disabler_usb_debug_desc')"
            :disabled="adbBusy || !adbEnabled"
          />
          <MiuixSwitchPreference
            v-model="adbOemUnlock"
            :title="i18n.t('adb_disabler_oem_unlock')"
            :summary="i18n.t('adb_disabler_oem_unlock_desc')"
            :disabled="adbBusy || !adbEnabled"
          />
          <div class="confirm-actions">
            <MiuixButton :disabled="adbBusy" @click="close">{{ i18n.t('functional_button_cancel') }}</MiuixButton>
            <MiuixButton type="primary" :disabled="adbBusy" @click="void applyAdbDisabler()">
              <MiuixProgressIndicator v-if="adbBusy" type="circular" :size="18" />
              {{ i18n.t('functional_button_apply') }}
            </MiuixButton>
          </div>
        </div>
      </template>
    </MiuixDialog>

    <PifFingerprintDialog
      ref="pifDialog"
      v-model="pifOpen"
      :cli="cli"
      @notify="notify"
      @changed="refreshIdentity(true); refreshActivity()"
    />
    <MiuixSnackbarHost />
  </div>
</template>

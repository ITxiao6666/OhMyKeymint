import type { MdDialog } from '@material/web/all'
import '@material/web/button/filled-button.js'
import '@material/web/button/outlined-button.js'
import '@material/web/dialog/dialog.js'
import '@material/web/divider/divider.js'
import '@material/web/fab/fab.js'
import '@material/web/icon/icon.js'
import '@material/web/iconbutton/filled-tonal-icon-button.js'
import '@material/web/iconbutton/icon-button.js'
import '@material/web/menu/menu-item.js'
import '@material/web/menu/menu.js'
import '@material/web/progress/circular-progress.js'
import '@material/web/radio/radio.js'
import '@material/web/ripple/ripple.js'
import '@material/web/switch/switch.js'
import '@material/web/textfield/outlined-text-field.js'
import { AppList } from './app_list/app_list'
import { appearance } from './appearance'
import { Cli, type KeyboxRevocationStatus } from './cli'
import { ConfigOhMyKeyMint } from './config_ohmykeymint'
import { KeyboxDialog } from './dialog/keybox'
import { applyDialogAnimation } from './dialog/animation'
import { FileSelector } from './file_selector/file_selector'
import { PifFingerprintDialog } from './dialog/pif_fingerprint'
import { SystemAppDialog } from './dialog/system_app'
import { History } from './history'
import { i18n } from './i18n'
import { Keybind } from './keybind'
import { BottomNavigation, type PageId } from './navigation/bottom_navigation'
import { AppTargetsPage } from './pages/app_targets_page'
import { HomePage } from './pages/home_page'
import { SettingsPage } from './pages/settings_page'
import { ToolsPage } from './pages/tools_page'
import { fetchLatestSecurityPatch } from './security_patch'
import { Snackbar } from './snackbar/snackbar'
import { isDev } from './utils/dev'
import './style.scss'
import './miuix.scss'

await i18n.init()

const root = document.querySelector<HTMLDivElement>('#app')!
root.innerHTML = /* html */ `
  <main class="app-shell miuix-app">
    <div class="page-stack"></div>
  </main>
  <section class="floating-content miuix-snackbar-host">
    <div class="snackbar hide" role="status" aria-live="polite">
      <div class="snackbar-text"></div>
    </div>
  </section>
  <section class="overlay-content miuix-overlay-layer"></section>
  <section class="dialog-content miuix-dialog-layer"></section>
`

const cli = new Cli()
const config = new ConfigOhMyKeyMint(cli)
const appList = new AppList(config)
const snackbar = new Snackbar()
const history = new History()
const keybind = new Keybind()

const homePage = new HomePage()
const toolsPage = new ToolsPage()
const settingsPage = new SettingsPage(appearance)
const targetsPage = new AppTargetsPage(appList)
const navigation = new BottomNavigation()

const pageStack = root.querySelector<HTMLElement>('.page-stack')!
const pages = new Map<PageId, HTMLElement>([
  ['home', homePage.getElement()],
  ['tools', toolsPage.getElement()],
  ['settings', settingsPage.getElement()],
])
pageStack.append(...pages.values())
root.appendChild(navigation.getElement())
root.querySelector<HTMLElement>('.overlay-content')!.appendChild(targetsPage.getElement())

let pageHistoryActive = false
function showPage(page: PageId): void {
  for (const [id, element] of pages) element.hidden = id !== page
  window.scrollTo(0, 0)
}

navigation.onChange(page => {
  showPage(page)
  if (page === 'home') {
    void refreshHomeIdentity()
    void refreshHomeActivity()
  }
  if (page !== 'home' && !pageHistoryActive) {
    pageHistoryActive = true
    history.push('main-page', () => {
      pageHistoryActive = false
      navigation.select('home', false)
      showPage('home')
    })
  } else if (page === 'home' && pageHistoryActive) {
    pageHistoryActive = false
    history.consume('main-page')
  }
})

let targetsOpen = false
let targetsOpenRefreshTimer: number | null = null
let foregroundRefreshTimer: number | null = null
let lastForegroundRefreshAt = Number.NEGATIVE_INFINITY
let appListReloading = false
let appListReloadQueued = false
let appListReloadQueuedReadConfig = false
let appListReloadQueuedScrollToTop = false
function openTargets(): void {
  if (targetsOpen) return
  targetsOpen = true
  document.body.classList.add('targets-open')
  targetsPage.show()
  // Refresh installed packages every time the page opens. Keep the in-memory
  // target selection so returning from an app installer cannot discard edits.
  // Let the overlay finish sliding in before crossing the synchronous KSU bridge.
  targetsOpenRefreshTimer = window.setTimeout(() => {
    targetsOpenRefreshTimer = null
    if (targetsOpen) void reloadAppList(false, false)
  }, 220)
  history.push('app-targets', () => {
    targetsOpen = false
    document.body.classList.remove('targets-open')
    targetsPage.close()
  })
}

function closeTargets(): void {
  if (!targetsOpen) return
  targetsOpen = false
  if (targetsOpenRefreshTimer !== null) {
    window.clearTimeout(targetsOpenRefreshTimer)
    targetsOpenRefreshTimer = null
  }
  if (foregroundRefreshTimer !== null) {
    window.clearTimeout(foregroundRefreshTimer)
    foregroundRefreshTimer = null
  }
  document.body.classList.remove('targets-open')
  targetsPage.close()
  history.consume('app-targets')
}

async function reloadAppList(scrollToTop: boolean, readConfig = true): Promise<void> {
  if (appListReloading) {
    appListReloadQueued = true
    appListReloadQueuedReadConfig ||= readConfig
    appListReloadQueuedScrollToTop ||= scrollToTop
    return
  }
  appListReloading = true
  targetsPage.setApplyEnabled(false)
  if (readConfig) homePage.setModuleStatus('loading')
  let readError: unknown = null

  if (readConfig) {
    try {
      await config.read()
    } catch (error) {
      readError = error
    }
  }

  const entriesChanged = await appList.fetch()
  appList.syncSystemAppsWithConfig()
  if (entriesChanged || readConfig) appList.renderAppList(targetsPage.listContainer)
  targetsPage.setApplyEnabled(config.isWritable)
  if (readConfig) homePage.setModuleStatus(readError === null ? 'ready' : 'error')

  if (scrollToTop) targetsPage.listContainer.scrollTo({ top: 0 })
  if (readError !== null) {
    console.error('Unable to load the OMK scoop list:', readError)
    snackbar.show(i18n.t('prompt_load_error'), false, 6000)
  }
  appListReloading = false
  if (appListReloadQueued) {
    const queuedReadConfig = appListReloadQueuedReadConfig
    const queuedScrollToTop = appListReloadQueuedScrollToTop
    appListReloadQueued = false
    appListReloadQueuedReadConfig = false
    appListReloadQueuedScrollToTop = false
    void reloadAppList(queuedScrollToTop, queuedReadConfig)
  }
}

function refreshTargetsWhenForegrounded(): void {
  if (!targetsOpen || document.visibilityState !== 'visible' || foregroundRefreshTimer !== null) return
  if (performance.now() - lastForegroundRefreshAt < 500) return
  foregroundRefreshTimer = window.setTimeout(() => {
    foregroundRefreshTimer = null
    if (targetsOpen && document.visibilityState === 'visible') {
      lastForegroundRefreshAt = performance.now()
      void reloadAppList(false, false)
    }
  }, 120)
}

document.addEventListener('visibilitychange', refreshTargetsWhenForegrounded)
window.addEventListener('focus', refreshTargetsWhenForegrounded)

async function saveTarget(): Promise<boolean> {
  if (!config.isWritable) {
    snackbar.show(i18n.t('prompt_load_error'), false, 6000)
    return false
  }

  targetsPage.setApplyEnabled(false)
  try {
    await appList.save()
    await refreshHomeActivity()
    snackbar.show(i18n.t('prompt_saved_target'))
    return true
  } catch (error) {
    console.error('Unable to save the OMK scoop list:', error)
    snackbar.show(i18n.t('prompt_save_error'), false)
    return false
  } finally {
    targetsPage.setApplyEnabled(config.isWritable)
  }
}

targetsPage.on('target-select-all', () => appList.selectAll())
targetsPage.on('target-deselect-all', () => appList.deselectAll())
targetsPage.on('target-refresh', () => void reloadAppList(true, false))
targetsPage.on('target-add-system-app', () => systemAppDialog.show())
targetsPage.on('target-close', () => closeTargets())
targetsPage.on('target-apply', () => {
  void saveTarget().then(saved => {
    if (saved) closeTargets()
  })
})

toolsPage.on('tool-open-app-targets', () => openTargets())

const dialogContent = root.querySelector<HTMLElement>('.dialog-content')!
const systemAppDialog = new SystemAppDialog(appList)
dialogContent.appendChild(systemAppDialog.getElement())
systemAppDialog.initAnimation()

const fileSelector = new FileSelector()
dialogContent.appendChild(fileSelector.getElement())
fileSelector.initAnimation()

const keyboxDialog = new KeyboxDialog(cli, snackbar, fileSelector)
dialogContent.appendChild(keyboxDialog.getElement())
keyboxDialog.initAnimation()
toolsPage.on('tool-install-keybox', () => keyboxDialog.choose())
dialogContent.querySelector('#keybox-dialog')?.addEventListener(
  'closed',
  () => {
    void refreshHomeIdentity(true)
    void refreshHomeActivity()
  },
)

const pifFingerprintDialog = new PifFingerprintDialog(cli, snackbar)
dialogContent.appendChild(pifFingerprintDialog.getElement())
pifFingerprintDialog.initAnimation()
toolsPage.on('tool-spoof-pif', () => pifFingerprintDialog.show())
dialogContent.querySelector('#pif-fingerprint-dialog')?.addEventListener(
  'closed',
  () => {
    void refreshHomeIdentity()
    void refreshHomeActivity()
  },
)

let homeRefreshGeneration = 0
let keyboxRevocationRequest: Promise<KeyboxRevocationStatus> | null = null

function requestKeyboxRevocation(force: boolean): Promise<KeyboxRevocationStatus> {
  if (!force && keyboxRevocationRequest !== null) return keyboxRevocationRequest

  const request = cli.checkKeyboxRevocation()
  keyboxRevocationRequest = request
  request.then(
    () => {
      if (keyboxRevocationRequest === request) keyboxRevocationRequest = null
    },
    () => {
      if (keyboxRevocationRequest === request) keyboxRevocationRequest = null
    },
  )
  return request
}

async function refreshKeyboxRevocation(generation: number, force: boolean): Promise<void> {
  try {
    const status = await requestKeyboxRevocation(force)
    if (generation === homeRefreshGeneration) homePage.setKeyboxRevocation(status)
  } catch (error) {
    if (generation !== homeRefreshGeneration) return
    homePage.setKeyboxRevocation('unknown')
    console.error('Unable to check the current Keybox revocation status:', error)
  }
}

async function refreshHomeIdentity(forceKeyboxRevocation = false): Promise<void> {
  if (forceKeyboxRevocation) keyboxRevocationRequest = null
  const generation = ++homeRefreshGeneration

  if (isDev()) {
    homePage.setKeyboxStatus('custom', 'google_remote', 'tee', 'not_listed')
    homePage.setTeeStatus('normal')
    homePage.setSecurityPatch('2026-08-01')
    homePage.setSpoofedDevice('Google Pixel 9 Pro')
    return
  }

  homePage.setKeyboxLoading()

  const [keyboxResult, patchResult, teeResult, pifResult] = await Promise.allSettled([
    cli.getKeyboxState(),
    cli.getSystemSecurityPatch(),
    cli.getTeeStatus(),
    cli.getPifFingerprintState(),
  ])
  if (generation !== homeRefreshGeneration) return

  if (keyboxResult.status === 'fulfilled') {
    const state = keyboxResult.value
    homePage.setKeyboxStatus(
      state.valid ? (state.bundled ? 'bundled' : 'custom') : 'invalid',
      state.source,
      state.level,
      state.valid ? 'checking' : state.revocation,
    )
    if (state.valid) void refreshKeyboxRevocation(generation, forceKeyboxRevocation)
  } else {
    homePage.setKeyboxStatus('error')
    console.error('Unable to load the current Keybox state:', keyboxResult.reason)
  }

  if (patchResult.status === 'fulfilled') {
    homePage.setSecurityPatch(patchResult.value)
  } else {
    console.error('Unable to load the current security patch:', patchResult.reason)
  }

  if (teeResult.status === 'fulfilled') {
    homePage.setTeeStatus('normal')
  } else {
    homePage.setTeeStatus('error')
    console.error('Unable to verify the OMK TEE service:', teeResult.reason)
  }

  if (pifResult.status === 'fulfilled') {
    const state = pifResult.value
    const model = state.enabled
      ? (/^google\s/i.test(state.model) ? state.model : `Google ${state.model}`)
      : null
    homePage.setSpoofedDevice(model)
  } else {
    console.error('Unable to load the current PIF fingerprint:', pifResult.reason)
  }
}

let homeActivityGeneration = 0
async function refreshHomeActivity(): Promise<void> {
  const generation = ++homeActivityGeneration
  if (isDev()) {
    const now = Math.floor(Date.now() / 1000)
    homePage.setActivities([
      { action: 'keybox_changed', detail: '', timestamp: now - 345_600 },
      {
        action: 'pif_enabled',
        detail: JSON.stringify({ model: 'Google Pixel 9 Pro', securityPatch: '2026-08-05' }),
        timestamp: now - 259_200,
      },
      { action: 'targets_saved', detail: '2', timestamp: now - 86_400 },
      { action: 'security_patch_synced', detail: '2026-08-01', timestamp: now - 3600 },
      { action: 'widevine_installed', detail: '', timestamp: now - 90 },
    ])
    return
  }

  try {
    const entries = await cli.getActivityLog()
    if (generation === homeActivityGeneration) homePage.setActivities(entries)
  } catch (error) {
    if (generation !== homeActivityGeneration) return
    homePage.setActivityError()
    console.error('Unable to load WebUI activity:', error)
  }
}

homePage.onClearActivities(() => {
  void (async () => {
    homePage.setActivityClearBusy(true)
    try {
      if (!isDev()) await cli.clearActivityLog()
      homePage.setActivities([])
      snackbar.show(i18n.t('home_activity_cleared'))
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.error('Unable to clear WebUI activity:', error)
      snackbar.show(i18n.t('home_activity_clear_error', detail), false, 6000)
    } finally {
      homePage.setActivityClearBusy(false)
    }
  })()
})

const widevineDialog = document.createElement('md-dialog') as MdDialog
widevineDialog.id = 'widevine-dialog'
widevineDialog.classList.add('miuix-dialog')
widevineDialog.innerHTML = /* html */ `
  <div slot="headline" class="widevine-dialog-title"></div>
  <div slot="content" class="widevine-dialog-content">
    <md-icon aria-hidden="true">warning</md-icon>
    <p></p>
  </div>
  <div slot="actions">
    <md-outlined-button class="widevine-cancel"></md-outlined-button>
    <md-filled-button class="widevine-confirm"></md-filled-button>
  </div>
`
widevineDialog.querySelector<HTMLElement>('.widevine-dialog-title')!.textContent =
  i18n.t('widevine_confirm_title')
widevineDialog.querySelector<HTMLElement>('.widevine-dialog-content p')!.textContent =
  i18n.t('widevine_confirm_message')
const widevineCancel = widevineDialog.querySelector<HTMLElement>('.widevine-cancel')!
widevineCancel.textContent = i18n.t('functional_button_cancel')
widevineCancel.onclick = () => widevineDialog.close()
const widevineConfirm = widevineDialog.querySelector<HTMLElement>('.widevine-confirm')!
widevineConfirm.textContent = i18n.t('functional_button_apply')
dialogContent.appendChild(widevineDialog)
applyDialogAnimation(widevineDialog)

let widevineBusy = false
async function installWidevineL1(): Promise<void> {
  if (widevineBusy) return
  widevineBusy = true
  toolsPage.setActionBusy('tool-install-widevine', true)
  snackbar.showLoading(i18n.t('widevine_installing'))
  try {
    if (!isDev()) await cli.installWidevineL1()
    await refreshHomeActivity()
    snackbar.show(i18n.t('prompt_widevine_installed'))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    console.error('Unable to install the Widevine L1 attestation keys:', error)
    snackbar.show(i18n.t('prompt_widevine_install_error', detail), false, 6000)
  } finally {
    toolsPage.setActionBusy('tool-install-widevine', false)
    widevineBusy = false
  }
}

toolsPage.on('tool-install-widevine', () => {
  if (!widevineBusy) widevineDialog.show()
})
widevineConfirm.onclick = () => {
  if (widevineBusy) return
  widevineDialog.close()
  void installWidevineL1()
}

let securityPatchBusy = false
async function syncSecurityPatch(): Promise<void> {
  if (securityPatchBusy) return
  securityPatchBusy = true
  toolsPage.setSecurityPatchBusy('tool-sync-security-patch')
  snackbar.showLoading(i18n.t('menu_sync_security_patch'))
  try {
    if (isDev()) {
      snackbar.show(i18n.t('prompt_security_patch_synced'))
      return
    }
    const date = await fetchLatestSecurityPatch(() => cli.fetchSecurityBulletin())
    const appliedDate = await cli.syncSecurityPatch(date)
    homePage.setSecurityPatch(appliedDate)
    await refreshHomeActivity()
    snackbar.show(i18n.t('prompt_security_patch_sync_complete', appliedDate))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    console.error('Unable to sync the security patch:', error)
    snackbar.show(i18n.t('prompt_security_patch_sync_error', detail), false, 6000)
  } finally {
    toolsPage.setSecurityPatchBusy(null)
    securityPatchBusy = false
  }
}
toolsPage.on('tool-sync-security-patch', () => void syncSecurityPatch())

async function restoreDefaultSecurityPatch(): Promise<void> {
  if (securityPatchBusy) return
  securityPatchBusy = true
  toolsPage.setSecurityPatchBusy('tool-restore-security-patch')
  snackbar.showLoading(i18n.t('menu_restore_default_security_patch'))
  try {
    if (!isDev()) {
      await cli.restoreDefaultSecurityPatch()
      await refreshHomeIdentity()
      await refreshHomeActivity()
    }
    snackbar.show(i18n.t('prompt_security_patch_restored_default'))
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    console.error('Unable to restore the default security patch:', error)
    snackbar.show(i18n.t('prompt_security_patch_restore_error', detail), false, 6000)
  } finally {
    toolsPage.setSecurityPatchBusy(null)
    securityPatchBusy = false
  }
}
toolsPage.on('tool-restore-security-patch', () => void restoreDefaultSecurityPatch())

dialogContent.querySelectorAll<MdDialog>('md-dialog').forEach((dialog, index) => {
  const id = dialog.id || `md-dialog-${index}`
  const closeFromHistory = (): void => {
    if (id === 'keybox-dialog') {
      if (!keyboxDialog.close()) {
        window.setTimeout(() => {
          if (!keyboxDialog.close()) history.push(id, closeFromHistory)
        }, 0)
      }
      return
    }
    if (id === 'file-selector-dialog') {
      fileSelector.close()
      return
    }
    if (id === 'pif-fingerprint-dialog') {
      if (!pifFingerprintDialog.close()) {
        window.setTimeout(() => {
          if (!pifFingerprintDialog.close()) history.push(id, closeFromHistory)
        }, 0)
      }
      return
    }
    dialog.close()
  }
  dialog.addEventListener('open', () => history.push(id, closeFromHistory))
  dialog.addEventListener('closed', () => history.consume(id))
})

keybind.on('keybind-select-all', () => {
  if (targetsOpen) appList.selectAll()
})
keybind.on('keybind-deselect-all', () => {
  if (targetsOpen) appList.deselectAll()
})
keybind.on('keybind-search', () => {
  if (!targetsOpen) openTargets()
  window.setTimeout(() => targetsPage.focusSearch(), 0)
})
keybind.on('keybind-save', () => {
  if (targetsOpen) void saveTarget()
})
keybind.on('keybind-esc', () => history.back())

window.onscroll = () => {
  root.querySelectorAll('md-menu').forEach(menu => menu.close())
}

await Promise.all([reloadAppList(false), refreshHomeIdentity(), refreshHomeActivity()])

import { i18n } from '../i18n'
import type {
  ActivityEntry,
  KeyboxLevel,
  KeyboxRevocationStatus,
  KeyboxSource,
} from '../cli'
import './pages.scss'

export type ModuleStatus = 'loading' | 'ready' | 'error'
export type KeyboxStatus = 'loading' | 'bundled' | 'custom' | 'invalid' | 'error'
export type TeeStatus = 'loading' | 'normal' | 'error'

function translate(key: string, fallback: string, ...args: unknown[]): string {
  const value = i18n.t(key, ...args)
  if (value !== key) return value
  let index = 0
  return fallback.replace(/%s/g, () => String(args[index++] ?? ''))
}

export class HomePage {
  #element: HTMLElement | null = null
  #status: ModuleStatus = 'loading'
  #keyboxStatus: KeyboxStatus = 'loading'
  #keyboxSource: KeyboxSource = 'unknown'
  #keyboxLevel: KeyboxLevel = 'unknown'
  #keyboxRevocation: KeyboxRevocationStatus = 'not_checked'
  #teeStatus: TeeStatus = 'loading'
  #securityPatch: string | null = null
  #spoofedDevice: string | null | undefined
  #activities: ActivityEntry[] = []
  #activityStatus: 'loading' | 'ready' | 'error' = 'loading'
  #activitiesExpanded = false
  #activityClearBusy = false
  #clearActivitiesCallback: (() => void) | null = null

  getElement(): HTMLElement {
    const page = document.createElement('section')
    page.id = 'page-home'
    page.className = 'app-page miuix-page home-page'
    page.dataset.page = 'home'
    page.innerHTML = /* html */ `
      <header class="page-heading miuix-top-app-bar home-heading">
        <div class="home-brand">
          <h1>Oh My Keymint</h1>
        </div>
        <div class="home-module-status" data-status="loading">
          <md-icon aria-hidden="true">hourglass_top</md-icon>
          <strong class="module-status-value"></strong>
        </div>
      </header>
      <div class="home-identity-grid" aria-live="polite">
        <article class="identity-card miuix-card keybox-summary" data-status="loading">
          <div class="identity-section">
            <span class="identity-label keybox-label"></span>
            <strong class="identity-primary keybox-source-value">&mdash;</strong>
          </div>
          <div class="identity-section keybox-level-section">
            <span class="identity-label keybox-level-label"></span>
            <strong class="identity-secondary keybox-level-value">&mdash;</strong>
          </div>
          <div class="identity-section identity-footer">
            <span class="identity-label keybox-revocation-label"></span>
            <strong class="identity-secondary keybox-revocation-value"></strong>
          </div>
        </article>
        <article class="identity-card miuix-card device-summary">
          <div class="identity-section">
            <span class="identity-label security-patch-label"></span>
            <strong class="identity-primary security-patch-value">&mdash;</strong>
          </div>
          <div class="identity-section">
            <span class="identity-label tee-status-label"></span>
            <strong class="identity-secondary tee-status-value"></strong>
          </div>
          <div class="identity-section">
            <span class="identity-label spoofed-device-label"></span>
            <strong class="identity-secondary spoofed-device-value">&mdash;</strong>
          </div>
        </article>
      </div>
      <section class="home-activity miuix-card" aria-labelledby="recent-activity-title">
        <header class="activity-heading">
          <h2 id="recent-activity-title"></h2>
          <span class="activity-count"></span>
          <button type="button" class="activity-icon-button activity-clear">
            <md-icon aria-hidden="true">delete</md-icon>
          </button>
        </header>
        <div class="activity-content" aria-live="polite"></div>
        <button type="button" class="activity-toggle" hidden></button>
      </section>
    `

    page.querySelector<HTMLElement>('.keybox-label')!.textContent =
      translate('home_keybox', 'Keybox')
    page.querySelector<HTMLElement>('.keybox-level-label')!.textContent =
      translate('home_keybox_security_level', 'Security Level')
    page.querySelector<HTMLElement>('.keybox-revocation-label')!.textContent =
      translate('home_keybox_revocation', 'Certificate status')
    page.querySelector<HTMLElement>('.security-patch-label')!.textContent =
      translate('home_security_patch', 'Security patch')
    page.querySelector<HTMLElement>('.tee-status-label')!.textContent =
      translate('home_tee_status', 'TEE status')
    page.querySelector<HTMLElement>('.spoofed-device-label')!.textContent =
      translate('home_spoofed_device', 'Spoofed device fingerprint')
    page.querySelector<HTMLElement>('#recent-activity-title')!.textContent =
      translate('home_recent_activity', 'Recent activity')
    const clearButton = page.querySelector<HTMLButtonElement>('.activity-clear')!
    const clearLabel = translate('home_activity_clear', 'Clear activity')
    clearButton.title = clearLabel
    clearButton.setAttribute('aria-label', clearLabel)
    clearButton.onclick = () => {
      if (!clearButton.disabled) this.#clearActivitiesCallback?.()
    }
    page.querySelector<HTMLButtonElement>('.activity-toggle')!.onclick = () => {
      this.#activitiesExpanded = !this.#activitiesExpanded
      this.#renderActivities()
    }

    this.#element = page
    this.#renderStatus()
    this.#renderDeviceOverview()
    this.#renderActivities()
    return page
  }

  setModuleStatus(status: ModuleStatus): void {
    this.#status = status
    this.#renderStatus()
  }

  setKeyboxStatus(
    value: Exclude<KeyboxStatus, 'loading'>,
    source: KeyboxSource = 'unknown',
    level: KeyboxLevel = 'unknown',
    revocation: KeyboxRevocationStatus = 'not_checked',
  ): void {
    this.#keyboxStatus = value
    this.#keyboxSource = source
    this.#keyboxLevel = level
    this.#keyboxRevocation = revocation
    this.#renderDeviceOverview()
  }

  setKeyboxLoading(): void {
    this.#keyboxStatus = 'loading'
    this.#keyboxSource = 'unknown'
    this.#keyboxLevel = 'unknown'
    this.#keyboxRevocation = 'checking'
    this.#renderDeviceOverview()
  }

  setKeyboxRevocation(value: KeyboxRevocationStatus): void {
    this.#keyboxRevocation = value
    this.#renderDeviceOverview()
  }

  setTeeStatus(value: Exclude<TeeStatus, 'loading'>): void {
    this.#teeStatus = value
    this.#renderDeviceOverview()
  }

  setSecurityPatch(value: string): void {
    this.#securityPatch = value
    this.#renderDeviceOverview()
  }

  setSpoofedDevice(value: string | null): void {
    this.#spoofedDevice = value
    this.#renderDeviceOverview()
  }

  setActivities(entries: ActivityEntry[]): void {
    this.#activities = [...entries].reverse()
    this.#activityStatus = 'ready'
    this.#activitiesExpanded = false
    this.#renderActivities()
  }

  setActivityError(): void {
    this.#activities = []
    this.#activityStatus = 'error'
    this.#activitiesExpanded = false
    this.#renderActivities()
  }

  setActivityClearBusy(busy: boolean): void {
    this.#activityClearBusy = busy
    this.#renderActivities()
  }

  onClearActivities(callback: () => void): void {
    this.#clearActivitiesCallback = callback
  }

  #renderStatus(): void {
    const value = this.#element?.querySelector<HTMLElement>('.module-status-value')
    const icon = this.#element?.querySelector<HTMLElement>('.home-module-status md-icon')
    const item = this.#element?.querySelector<HTMLElement>('.home-module-status')
    if (!value || !icon || !item) return

    const states: Record<ModuleStatus, { label: string, icon: string }> = {
      loading: { label: translate('home_status_loading', 'Checking'), icon: 'hourglass_top' },
      ready: { label: translate('home_status_running', 'Running'), icon: 'check_circle' },
      error: { label: translate('home_status_error', 'Needs attention'), icon: 'error' },
    }
    value.textContent = states[this.#status].label
    icon.textContent = states[this.#status].icon
    item.dataset.status = this.#status
    item.setAttribute(
      'aria-label',
      `${translate('home_module_status', 'Module status')}: ${states[this.#status].label}`,
    )
  }

  #renderDeviceOverview(): void {
    const patch = this.#element?.querySelector<HTMLElement>('.security-patch-value')
    const device = this.#element?.querySelector<HTMLElement>('.spoofed-device-value')
    const keybox = this.#element?.querySelector<HTMLElement>('.keybox-summary')
    const keyboxSource = this.#element?.querySelector<HTMLElement>('.keybox-source-value')
    const keyboxLevel = this.#element?.querySelector<HTMLElement>('.keybox-level-value')
    const keyboxRevocation = this.#element?.querySelector<HTMLElement>('.keybox-revocation-value')
    const teeStatus = this.#element?.querySelector<HTMLElement>('.tee-status-value')

    const keyboxStates: Record<KeyboxStatus, {
      source: string
      level: string
      revocation: string
      revocationCode: string
    }> = {
      loading: {
        source: '\u2014',
        level: translate('home_keybox_level_unknown', 'Unknown'),
        revocation: translate('home_keybox_status_checking', 'Checking'),
        revocationCode: 'checking',
      },
      bundled: {
        source: translate('home_keybox_bundled', 'Built-in Keybox'),
        level: this.#keyboxLevelLabel(),
        revocation: this.#keyboxRevocationLabel(),
        revocationCode: this.#keyboxRevocationCode(),
      },
      custom: {
        source: this.#keyboxSourceLabel(),
        level: this.#keyboxLevelLabel(),
        revocation: this.#keyboxRevocationLabel(),
        revocationCode: this.#keyboxRevocationCode(),
      },
      invalid: {
        source: translate('home_keybox_invalid', 'Invalid Keybox'),
        level: translate('home_keybox_level_unknown', 'Unknown'),
        revocation: translate('home_keybox_local_invalid', 'Local validation failed'),
        revocationCode: 'invalid',
      },
      error: {
        source: '\u2014',
        level: translate('home_keybox_level_unknown', 'Unknown'),
        revocation: translate('home_keybox_revocation_check_failed', 'Check failed'),
        revocationCode: 'unknown',
      },
    }
    if (keybox) keybox.dataset.status = this.#keyboxStatus
    if (keyboxSource) {
      keyboxSource.textContent = keyboxStates[this.#keyboxStatus].source
      keyboxSource.dataset.source = this.#keyboxStatus === 'custom'
        ? this.#keyboxSource
        : this.#keyboxStatus
      keyboxSource.style.removeProperty('font-size')
      if (keyboxSource.dataset.source === 'google_hardware'
        || keyboxSource.dataset.source === 'google_remote') {
        requestAnimationFrame(() => {
          if (!keyboxSource.isConnected || !keyboxSource.dataset.source?.startsWith('google_')) return
          const availableWidth = keyboxSource.clientWidth
          const contentWidth = keyboxSource.scrollWidth
          if (availableWidth <= 0 || contentWidth <= availableWidth) return
          const fittedSize = Math.max(10, Math.floor(160 * availableWidth / contentWidth) / 10)
          keyboxSource.style.fontSize = `${fittedSize}px`
        })
      }
    }
    if (keyboxLevel) {
      keyboxLevel.textContent = keyboxStates[this.#keyboxStatus].level
      keyboxLevel.dataset.level = this.#keyboxLevel
    }
    if (keyboxRevocation) {
      keyboxRevocation.textContent = keyboxStates[this.#keyboxStatus].revocation
      keyboxRevocation.dataset.status = keyboxStates[this.#keyboxStatus].revocationCode
    }
    if (teeStatus) {
      const teeStates: Record<TeeStatus, string> = {
        loading: translate('home_status_loading', 'Checking'),
        normal: translate('home_tee_normal', 'Normal'),
        error: translate('home_status_error', 'Needs attention'),
      }
      teeStatus.textContent = teeStates[this.#teeStatus]
      teeStatus.dataset.status = this.#teeStatus
    }
    if (patch) patch.textContent = this.#securityPatch ?? '\u2014'
    if (device) {
      device.textContent = this.#spoofedDevice === null
        ? translate('pif_disabled', 'Disabled')
        : this.#spoofedDevice ?? '\u2014'
    }
  }

  #keyboxSourceLabel(): string {
    switch (this.#keyboxSource) {
      case 'google_hardware':
        return translate('home_keybox_hardware', 'Google hardware root certificate')
      case 'google_remote':
        return translate('home_keybox_remote', 'Google remote key provisioning')
      case 'unknown':
        return translate('home_keybox_unknown', 'Unknown key')
    }
  }

  #keyboxLevelLabel(): string {
    switch (this.#keyboxLevel) {
      case 'tee':
        return translate('home_keybox_tee', 'TEE')
      case 'strongbox':
        return translate('home_keybox_strongbox', 'StrongBox')
      case 'unknown':
        return translate('home_keybox_level_unknown', 'Unknown')
    }
  }

  #keyboxRevocationLabel(): string {
    switch (this.#keyboxRevocation) {
      case 'not_checked':
        return translate('home_keybox_status_not_checked', 'Not checked')
      case 'checking':
        return translate('home_keybox_status_checking', 'Checking')
      case 'not_listed':
        return translate('home_keybox_revocation_not_revoked', 'Not revoked')
      case 'suspended':
      case 'revoked':
        return translate('home_keybox_revocation_revoked', 'Revoked')
      case 'unknown':
        return translate('home_keybox_revocation_check_failed', 'Check failed')
    }
  }

  #keyboxRevocationCode(): string {
    return this.#keyboxRevocation === 'suspended' ? 'revoked' : this.#keyboxRevocation
  }

  #renderActivities(): void {
    const content = this.#element?.querySelector<HTMLElement>('.activity-content')
    const count = this.#element?.querySelector<HTMLElement>('.activity-count')
    const clearButton = this.#element?.querySelector<HTMLButtonElement>('.activity-clear')
    const toggle = this.#element?.querySelector<HTMLButtonElement>('.activity-toggle')
    if (!content || !count || !clearButton || !toggle) return

    count.textContent = translate('home_activity_events', '%s events', this.#activities.length)
    clearButton.disabled = this.#activityClearBusy
      || this.#activityStatus === 'loading'
      || (this.#activityStatus === 'ready' && this.#activities.length === 0)
    clearButton.toggleAttribute('aria-busy', this.#activityClearBusy)
    content.replaceChildren()

    if (this.#activityStatus !== 'ready' || this.#activities.length === 0) {
      const empty = document.createElement('div')
      empty.className = `activity-empty${this.#activityStatus === 'error' ? ' error' : ''}`
      const icon = document.createElement('md-icon')
      icon.setAttribute('aria-hidden', 'true')
      icon.textContent = this.#activityStatus === 'error'
        ? 'error_outline'
        : this.#activityStatus === 'loading' ? 'hourglass_top' : 'history'
      const label = document.createElement('span')
      label.textContent = this.#activityStatus === 'error'
        ? translate('home_activity_load_error', 'Unable to load activity')
        : this.#activityStatus === 'loading'
          ? translate('home_status_loading', 'Checking')
          : translate('home_activity_empty', 'No activity yet')
      empty.append(icon, label)
      content.appendChild(empty)
      toggle.hidden = true
      return
    }

    const list = document.createElement('ol')
    list.className = 'activity-list'
    const visible = this.#activitiesExpanded ? this.#activities : this.#activities.slice(0, 4)
    for (const entry of visible) list.appendChild(this.#createActivityRow(entry))
    content.appendChild(list)

    toggle.hidden = this.#activities.length <= 4
    toggle.textContent = this.#activitiesExpanded
      ? translate('home_activity_show_less', 'Show less')
      : translate('home_activity_show_all', 'Show all (%s)', this.#activities.length)
  }

  #createActivityRow(entry: ActivityEntry): HTMLLIElement {
    const { title, detail } = this.#describeActivity(entry)
    const row = document.createElement('li')
    row.className = 'activity-row'

    const status = document.createElement('span')
    status.className = 'activity-status-icon'
    const statusIcon = document.createElement('md-icon')
    statusIcon.setAttribute('aria-hidden', 'true')
    statusIcon.textContent = 'check'
    status.appendChild(statusIcon)

    const copy = document.createElement('button')
    copy.type = 'button'
    copy.className = 'activity-icon-button activity-copy'
    const copyLabel = translate('home_activity_copy', 'Copy activity')
    copy.title = copyLabel
    copy.setAttribute('aria-label', copyLabel)
    const copyIcon = document.createElement('md-icon')
    copyIcon.setAttribute('aria-hidden', 'true')
    copyIcon.textContent = 'content_copy'
    copy.appendChild(copyIcon)
    copy.onclick = () => void this.#copyActivity(copyIcon, title, detail, entry.timestamp)

    const text = document.createElement('span')
    text.className = 'activity-copy-text'
    const titleElement = document.createElement('strong')
    titleElement.className = 'activity-title'
    titleElement.textContent = title
    const detailElement = document.createElement('span')
    detailElement.className = 'activity-detail'
    detailElement.textContent = detail
    text.append(titleElement, detailElement)

    const time = document.createElement('time')
    time.className = 'activity-time'
    const date = new Date(entry.timestamp * 1000)
    time.dateTime = date.toISOString()
    time.title = new Intl.DateTimeFormat(i18n.lang, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(date)
    time.textContent = this.#relativeTime(entry.timestamp)

    row.append(status, text, time, copy)
    return row
  }

  #describeActivity(entry: ActivityEntry): { title: string, detail: string } {
    switch (entry.action) {
      case 'targets_saved':
        return {
          title: translate('prompt_saved_target', 'Config saved'),
          detail: translate('home_selected_apps', '%s apps selected', entry.detail),
        }
      case 'keybox_changed':
        return {
          title: translate('menu_replace_keybox', 'Change Keybox'),
          detail: translate('prompt_keybox_replaced', 'Keybox was changed and will reload automatically.'),
        }
      case 'widevine_installed':
        return {
          title: translate('tools_widevine', 'Widevine L1'),
          detail: translate('prompt_widevine_installed', 'Widevine L1 attestation keys installed.'),
        }
      case 'security_patch_synced':
        return {
          title: translate('menu_sync_security_patch', 'Sync security patch'),
          detail: translate(
            'prompt_security_patch_sync_complete',
            'Security patch synchronization complete for %s. Please reboot the device.',
            entry.detail,
          ),
        }
      case 'security_patch_restored':
        return {
          title: translate('menu_restore_default_security_patch', 'Restore default security patch'),
          detail: translate(
            'prompt_security_patch_restored_default',
            'Default security patch restored. Please reboot the device.',
          ),
        }
      case 'pif_enabled': {
        let model = entry.detail
        let securityPatch = ''
        try {
          const parsed = JSON.parse(entry.detail) as { model?: unknown, securityPatch?: unknown }
          if (typeof parsed.model === 'string') model = parsed.model
          if (typeof parsed.securityPatch === 'string') securityPatch = parsed.securityPatch
        } catch {
          // Older or manually edited records remain readable as plain text.
        }
        return {
          title: translate('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
          detail: translate(
            'prompt_pif_applied',
            'PIF fingerprint applied: %s, security patch %s.',
            model,
            securityPatch,
          ),
        }
      }
      case 'pif_disabled':
        return {
          title: translate('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
          detail: translate('prompt_pif_disabled', 'PIF fingerprint spoofing disabled.'),
        }
    }
  }

  #relativeTime(timestamp: number): string {
    const elapsedSeconds = Math.max(0, Math.round(Date.now() / 1000 - timestamp))
    const formatter = new Intl.RelativeTimeFormat(i18n.lang, { numeric: 'auto' })
    if (elapsedSeconds < 60) return formatter.format(-elapsedSeconds, 'second')
    if (elapsedSeconds < 3600) return formatter.format(-Math.round(elapsedSeconds / 60), 'minute')
    if (elapsedSeconds < 86_400) return formatter.format(-Math.round(elapsedSeconds / 3600), 'hour')
    if (elapsedSeconds < 2_592_000) {
      return formatter.format(-Math.round(elapsedSeconds / 86_400), 'day')
    }
    if (elapsedSeconds < 31_536_000) {
      return formatter.format(-Math.round(elapsedSeconds / 2_592_000), 'month')
    }
    return formatter.format(-Math.round(elapsedSeconds / 31_536_000), 'year')
  }

  async #copyActivity(
    icon: HTMLElement,
    title: string,
    detail: string,
    timestamp: number,
  ): Promise<void> {
    const date = new Intl.DateTimeFormat(i18n.lang, {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(new Date(timestamp * 1000))
    try {
      await navigator.clipboard.writeText(`${title}\n${detail}\n${date}`)
      icon.textContent = 'check'
      window.setTimeout(() => { icon.textContent = 'content_copy' }, 1200)
    } catch (error) {
      console.error('Unable to copy WebUI activity:', error)
    }
  }
}

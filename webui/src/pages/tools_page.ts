import { i18n } from '../i18n'
import './pages.scss'

export type ToolEvent =
  | 'tool-open-app-targets'
  | 'tool-install-keybox'
  | 'tool-sync-security-patch'
  | 'tool-restore-security-patch'
  | 'tool-install-widevine'
  | 'tool-spoof-pif'

interface ToolDefinition {
  event: ToolEvent
  icon: string
  titleKey: string
  titleFallback: string
  descriptionKey: string
  descriptionFallback: string
}

const APP_TOOLS: readonly ToolDefinition[] = [
  {
    event: 'tool-open-app-targets',
    icon: 'apps',
    titleKey: 'app_targets_title',
    titleFallback: 'App targets',
    descriptionKey: 'tools_app_targets_desc',
    descriptionFallback: 'Choose which installed apps are routed through Oh My Keymint.',
  },
]

const KEY_TOOLS: readonly ToolDefinition[] = [
  {
    event: 'tool-install-keybox',
    icon: 'upload_file',
    titleKey: 'menu_replace_keybox',
    titleFallback: 'Change Keybox',
    descriptionKey: 'tools_keybox_desc',
    descriptionFallback: 'Choose a Keybox.xml file and install it for Oh My Keymint.',
  },
  {
    event: 'tool-install-widevine',
    icon: 'high_quality',
    titleKey: 'tools_widevine',
    titleFallback: 'Widevine L1',
    descriptionKey: 'tools_widevine_desc',
    descriptionFallback: 'Install an attestation key with the device KmInstallKeybox utility.',
  },
]

const IDENTITY_TOOLS: readonly ToolDefinition[] = [
  {
    event: 'tool-spoof-pif',
    icon: 'fingerprint',
    titleKey: 'menu_spoof_pif_fingerprint',
    titleFallback: 'Spoof PIF fingerprint',
    descriptionKey: 'tools_pif_desc',
    descriptionFallback: 'Fetch and apply a Pixel fingerprint for Play Integrity.',
  },
]

const DEVICE_TOOLS: readonly ToolDefinition[] = [
  {
    event: 'tool-sync-security-patch',
    icon: 'security_update',
    titleKey: 'menu_sync_security_patch',
    titleFallback: 'Sync security patch',
    descriptionKey: 'tools_sync_patch_desc',
    descriptionFallback: 'Apply the latest Google security patch date. A reboot is required.',
  },
  {
    event: 'tool-restore-security-patch',
    icon: 'settings_backup_restore',
    titleKey: 'menu_restore_default_security_patch',
    titleFallback: 'Restore default security patch',
    descriptionKey: 'tools_restore_patch_desc',
    descriptionFallback: 'Restore the device default security patch date. A reboot is required.',
  },
]

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

export class ToolsPage {
  #element: HTMLElement | null = null
  #callbacks = new Map<ToolEvent, Array<() => void>>()

  getElement(): HTMLElement {
    const page = document.createElement('section')
    page.id = 'page-tools'
    page.className = 'app-page tools-page'
    page.dataset.page = 'tools'
    page.hidden = true

    const heading = document.createElement('header')
    heading.className = 'page-heading'
    const title = document.createElement('h1')
    title.textContent = translate('tools_title', 'Tools')
    heading.appendChild(title)

    page.append(
      heading,
      this.#createGroup(translate('tools_app_management', 'App management'), APP_TOOLS),
      this.#createGroup(translate('tools_key_management', 'Key management'), KEY_TOOLS),
      this.#createGroup(
        translate('tools_fingerprint_spoofing', 'Fingerprint spoofing'),
        IDENTITY_TOOLS,
      ),
      this.#createGroup(translate('tools_security_patch', 'Set security patch'), DEVICE_TOOLS),
    )
    this.#element = page
    return page
  }

  on(event: ToolEvent, callback: () => void): void {
    const callbacks = this.#callbacks.get(event) ?? []
    callbacks.push(callback)
    this.#callbacks.set(event, callbacks)
  }

  setSecurityPatchBusy(activeEvent: 'tool-sync-security-patch' | 'tool-restore-security-patch' | null): void {
    const busy = activeEvent !== null
    for (const event of ['tool-sync-security-patch', 'tool-restore-security-patch'] as const) {
      const row = this.#element?.querySelector<HTMLButtonElement>(`[data-tool-event="${event}"]`)
      if (!row) continue
      const active = event === activeEvent
      row.disabled = busy
      row.toggleAttribute('aria-busy', active)
      row.querySelector<HTMLElement>('.tool-action-icon')?.toggleAttribute('hidden', active)
      row.querySelector<HTMLElement>('.tool-action-progress')?.toggleAttribute('hidden', !active)
    }
  }

  setActionBusy(event: ToolEvent, busy: boolean): void {
    const row = this.#element?.querySelector<HTMLButtonElement>(`[data-tool-event="${event}"]`)
    if (!row) return
    row.disabled = busy
    row.toggleAttribute('aria-busy', busy)
    row.querySelector<HTMLElement>('.tool-action-icon')?.toggleAttribute('hidden', busy)
    row.querySelector<HTMLElement>('.tool-action-progress')?.toggleAttribute('hidden', !busy)
  }

  #createGroup(title: string, definitions: readonly ToolDefinition[]): HTMLElement {
    const section = document.createElement('section')
    section.className = 'feature-section'
    const heading = document.createElement('h2')
    heading.className = 'section-title'
    heading.textContent = title
    const list = document.createElement('div')
    list.className = 'feature-list'
    for (const definition of definitions) list.appendChild(this.#createToolRow(definition))
    section.append(heading, list)
    return section
  }

  #createToolRow(definition: ToolDefinition): HTMLButtonElement {
    const row = document.createElement('button')
    row.type = 'button'
    row.className = 'feature-row'
    row.dataset.toolEvent = definition.event

    const iconBox = document.createElement('span')
    iconBox.className = 'feature-icon'
    const icon = document.createElement('md-icon')
    icon.className = 'tool-action-icon'
    icon.textContent = definition.icon
    icon.setAttribute('aria-hidden', 'true')
    const progress = document.createElement('md-circular-progress')
    progress.className = 'tool-action-progress'
    progress.setAttribute('indeterminate', '')
    progress.setAttribute('hidden', '')
    progress.setAttribute('aria-hidden', 'true')
    iconBox.append(icon, progress)

    const copy = document.createElement('span')
    copy.className = 'feature-copy'
    const title = document.createElement('span')
    title.className = 'feature-title'
    title.textContent = translate(definition.titleKey, definition.titleFallback)
    const description = document.createElement('span')
    description.className = 'feature-description'
    description.textContent = translate(definition.descriptionKey, definition.descriptionFallback)
    copy.append(title, description)

    const arrow = document.createElement('md-icon')
    arrow.className = 'feature-arrow'
    arrow.textContent = 'chevron_right'
    arrow.setAttribute('flip-icon-in-rtl', 'true')
    arrow.setAttribute('aria-hidden', 'true')
    const ripple = document.createElement('md-ripple')

    row.append(iconBox, copy, arrow, ripple)
    row.onclick = () => {
      if (row.disabled) return
      this.#callbacks.get(definition.event)?.forEach(callback => callback())
    }
    return row
  }
}

import type {
  MdDialog,
  MdFilledButton,
  MdOutlinedButton,
  MdRadio,
  MdSwitch,
} from '@material/web/all'
import { Cli, type PifDevice, type PifFingerprintState } from '../cli'
import { i18n } from '../i18n'
import { Snackbar } from '../snackbar/snackbar'
import { applyDialogAnimation } from './animation'
import './dialog.scss'

type LoadStatus = 'loading' | 'ready' | 'error'

const RANDOM_SELECTION = '__random__'

export class PifFingerprintDialog {
  #dialog: MdDialog | null = null
  #toggle: MdSwitch | null = null
  #applyButton: MdFilledButton | null = null
  #currentState: PifFingerprintState | null = null
  #devices: PifDevice[] = []
  #stateStatus: LoadStatus = 'loading'
  #catalogStatus: LoadStatus = 'loading'
  #stateError = ''
  #catalogError = ''
  #desiredEnabled = false
  #selectedProduct: string | null = RANDOM_SELECTION
  #loadGeneration = 0
  #busy = false
  readonly #cli: Cli
  readonly #snackbar: Snackbar

  constructor(cli: Cli, snackbar: Snackbar) {
    this.#cli = cli
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="pif-fingerprint-dialog">
        <div slot="headline"></div>
        <div slot="content" class="pif-dialog-content">
          <label class="pif-enable-row" for="pif-enabled">
            <span></span>
            <md-switch id="pif-enabled" icons></md-switch>
          </label>
          <div class="pif-requirement">
            <md-icon>info</md-icon>
            <span></span>
          </div>
          <div class="pif-current-config" aria-live="polite"></div>
          <div class="pif-device-panel" aria-live="polite"></div>
        </div>
        <div slot="actions">
          <md-outlined-button id="cancel-pif"></md-outlined-button>
          <md-filled-button id="apply-pif">
            <md-circular-progress class="pif-apply-progress" slot="icon" indeterminate hidden></md-circular-progress>
            <span class="pif-apply-label"></span>
          </md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#pif-fingerprint-dialog')!
    this.#toggle = fragment.querySelector<MdSwitch>('#pif-enabled')!
    this.#applyButton = fragment.querySelector<MdFilledButton>('#apply-pif')!

    fragment.querySelector<HTMLElement>('#pif-fingerprint-dialog [slot="headline"]')!.textContent =
      i18n.t('pif_fingerprint_title')
    fragment.querySelector<HTMLElement>('.pif-enable-row span')!.textContent =
      i18n.t('pif_enable_spoofing')
    this.#toggle.setAttribute('aria-label', i18n.t('pif_enable_spoofing'))
    fragment.querySelector<HTMLElement>('.pif-requirement span')!.textContent =
      i18n.t('pif_zygisk_next_required')

    this.#toggle.addEventListener('change', () => {
      if (this.#stateStatus !== 'ready' || this.#busy || !this.#toggle) return
      this.#desiredEnabled = this.#toggle.selected
      this.#renderPanel()
      this.#updateControls()
    })

    const cancelButton = fragment.querySelector<MdOutlinedButton>('#cancel-pif')!
    cancelButton.textContent = i18n.t('functional_button_cancel')
    cancelButton.onclick = () => this.close()
    this.#applyButton.onclick = () => void this.#apply()

    this.#dialog.addEventListener('closed', () => { this.#loadGeneration++ })
    for (const eventName of ['cancel', 'close']) {
      this.#dialog.addEventListener(eventName, event => {
        if (this.#busy) event.preventDefault()
      })
    }
    this.#render()
    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  show(): void {
    if (!this.#dialog || this.#dialog.open || this.#busy) return

    this.#currentState = null
    this.#devices = []
    this.#stateStatus = 'loading'
    this.#catalogStatus = 'loading'
    this.#stateError = ''
    this.#catalogError = ''
    this.#desiredEnabled = false
    this.#selectedProduct = RANDOM_SELECTION
    const generation = ++this.#loadGeneration
    this.#render()
    void this.#dialog.show()
    void this.#loadState(generation)
    void this.#loadCatalog(generation)
  }

  close(): boolean {
    if (this.#busy) return false
    this.#loadGeneration++
    void this.#dialog?.close()
    return true
  }

  async #loadState(generation: number): Promise<void> {
    try {
      const state = await this.#cli.getPifFingerprintState()
      if (!this.#isActive(generation)) return
      this.#currentState = state
      this.#desiredEnabled = state.enabled
      this.#selectedProduct = state.enabled ? state.product : RANDOM_SELECTION
      this.#stateStatus = 'ready'
      this.#reconcileSelection()
    } catch (error) {
      if (!this.#isActive(generation)) return
      this.#stateStatus = 'error'
      this.#stateError = error instanceof Error ? error.message : String(error)
    }
    this.#render()
  }

  async #loadCatalog(generation: number): Promise<void> {
    try {
      const devices = await this.#cli.listPifDevices()
      if (!this.#isActive(generation)) return
      this.#devices = devices
      this.#catalogStatus = 'ready'
      this.#reconcileSelection()
    } catch (error) {
      if (!this.#isActive(generation)) return
      this.#catalogStatus = 'error'
      this.#catalogError = error instanceof Error ? error.message : String(error)
    }
    this.#render()
  }

  #retryState(): void {
    if (this.#busy || !this.#dialog?.open) return
    this.#stateStatus = 'loading'
    this.#stateError = ''
    const generation = this.#loadGeneration
    this.#render()
    void this.#loadState(generation)
  }

  #retryCatalog(): void {
    if (this.#busy || !this.#dialog?.open) return
    this.#catalogStatus = 'loading'
    this.#catalogError = ''
    const generation = this.#loadGeneration
    this.#render()
    void this.#loadCatalog(generation)
  }

  #isActive(generation: number): boolean {
    return generation === this.#loadGeneration && Boolean(this.#dialog?.open)
  }

  #reconcileSelection(): void {
    if (this.#stateStatus !== 'ready' || this.#catalogStatus !== 'ready') return
    if (this.#selectedProduct === RANDOM_SELECTION) return
    if (this.#selectedProduct !== null
        && this.#devices.some(device => device.product === this.#selectedProduct)) return
    this.#selectedProduct = this.#currentState?.enabled ? null : RANDOM_SELECTION
  }

  #render(): void {
    if (!this.#dialog || !this.#toggle) return
    this.#toggle.selected = this.#desiredEnabled
    this.#renderCurrentConfig()
    this.#renderPanel()
    this.#updateControls()
  }

  #renderCurrentConfig(): void {
    const container = this.#dialog?.querySelector<HTMLElement>('.pif-current-config')
    if (!container) return
    container.replaceChildren()
    container.classList.toggle('hide', this.#stateStatus !== 'ready' || this.#currentState === null)
    if (this.#stateStatus !== 'ready' || this.#currentState === null) return

    const label = document.createElement('span')
    label.className = 'pif-current-label'
    label.textContent = i18n.t('pif_current_config')
    const value = document.createElement('span')
    value.className = 'pif-current-value'
    value.textContent = this.#currentState.enabled
      ? this.#currentState.model
      : i18n.t('pif_disabled')
    container.append(label, value)

    if (this.#currentState.enabled) {
      const patch = document.createElement('span')
      patch.className = 'pif-current-patch'
      patch.textContent = i18n.t('pif_security_patch', this.#currentState.security_patch)
      container.appendChild(patch)
    }
  }

  #renderPanel(): void {
    const panel = this.#dialog?.querySelector<HTMLElement>('.pif-device-panel')
    if (!panel) return
    panel.replaceChildren()

    if (this.#stateStatus === 'loading') {
      this.#appendLoading(panel, i18n.t('pif_loading_config'))
      return
    }
    if (this.#stateStatus === 'error') {
      this.#appendError(panel, i18n.t('pif_config_load_error'), this.#stateError, () => this.#retryState())
      return
    }
    if (!this.#desiredEnabled) {
      this.#appendStatus(panel, 'fingerprint_off', i18n.t('pif_disabled'))
      return
    }
    if (this.#catalogStatus === 'loading') {
      this.#appendLoading(panel, i18n.t('pif_loading_devices'))
      return
    }
    if (this.#catalogStatus === 'error') {
      this.#appendError(panel, i18n.t('pif_devices_load_error'), this.#catalogError, () => this.#retryCatalog())
      return
    }
    this.#appendDeviceList(panel)
  }

  #appendLoading(panel: HTMLElement, message: string): void {
    const status = document.createElement('div')
    status.className = 'pif-panel-status'
    status.setAttribute('role', 'status')
    const progress = document.createElement('md-circular-progress')
    progress.setAttribute('indeterminate', '')
    const text = document.createElement('span')
    text.textContent = message
    status.append(progress, text)
    panel.appendChild(status)
  }

  #appendStatus(panel: HTMLElement, iconName: string, message: string): void {
    const status = document.createElement('div')
    status.className = 'pif-panel-status'
    status.setAttribute('role', 'status')
    const icon = document.createElement('md-icon')
    icon.textContent = iconName
    const text = document.createElement('span')
    text.textContent = message
    status.append(icon, text)
    panel.appendChild(status)
  }

  #appendError(panel: HTMLElement, title: string, detail: string, retry: () => void): void {
    const status = document.createElement('div')
    status.className = 'pif-panel-status pif-panel-error'
    status.setAttribute('role', 'alert')
    const icon = document.createElement('md-icon')
    icon.textContent = 'error_outline'
    const titleElement = document.createElement('span')
    titleElement.className = 'pif-error-title'
    titleElement.textContent = title
    const detailElement = document.createElement('span')
    detailElement.className = 'pif-error-detail'
    detailElement.textContent = detail
    const retryButton = document.createElement('md-outlined-button')
    retryButton.textContent = i18n.t('functional_button_retry')
    retryButton.onclick = retry
    status.append(icon, titleElement, detailElement, retryButton)
    panel.appendChild(status)
  }

  #appendDeviceList(panel: HTMLElement): void {
    const list = document.createElement('div')
    list.className = 'pif-device-list'
    list.setAttribute('role', 'radiogroup')
    list.setAttribute('aria-label', i18n.t('pif_choose_device'))
    list.appendChild(this.#createDeviceOption(i18n.t('pif_random_device'), RANDOM_SELECTION))
    list.appendChild(document.createElement('md-divider'))
    for (const device of this.#devices) {
      list.appendChild(this.#createDeviceOption(device.model, device.product, device.product))
    }
    panel.appendChild(list)
  }

  #createDeviceOption(labelText: string, value: string, supportingText?: string): HTMLElement {
    const row = document.createElement('label')
    row.className = 'pif-device-option'
    const text = document.createElement('span')
    text.className = 'pif-device-text'
    const label = document.createElement('span')
    label.className = 'pif-device-name'
    label.textContent = labelText
    text.appendChild(label)
    if (supportingText) {
      const product = document.createElement('span')
      product.className = 'pif-device-product'
      product.textContent = supportingText
      text.appendChild(product)
    }

    const radio = document.createElement('md-radio') as MdRadio
    radio.name = 'pif-device'
    radio.value = value
    radio.checked = this.#selectedProduct === value
    radio.disabled = this.#busy
    radio.addEventListener('change', () => {
      if (!radio.checked || this.#busy) return
      this.#selectedProduct = value
      this.#updateControls()
    })
    row.append(text, radio)
    return row
  }

  async #apply(): Promise<void> {
    if (this.#busy || this.#stateStatus !== 'ready') return

    let device: PifDevice | undefined
    if (this.#desiredEnabled) {
      if (this.#catalogStatus !== 'ready' || this.#selectedProduct === null) return
      device = this.#selectedProduct === RANDOM_SELECTION
        ? this.#devices[Math.floor(Math.random() * this.#devices.length)]
        : this.#devices.find(item => item.product === this.#selectedProduct)
      if (!device) return
    }

    this.#setBusy(true)
    let succeeded = false
    try {
      if (device) {
        const state = await this.#cli.applyPifFingerprint(device.product)
        this.#currentState = state
        this.#snackbar.show(i18n.t('prompt_pif_applied', state.model, state.security_patch), true, 5000)
      } else {
        this.#currentState = await this.#cli.disablePifFingerprint()
        this.#snackbar.show(i18n.t('prompt_pif_disabled'))
      }
      succeeded = true
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.error('Unable to update PIF fingerprint spoofing:', error)
      this.#snackbar.show(i18n.t('prompt_pif_apply_error', detail), false, 6000)
    } finally {
      this.#setBusy(false)
      if (succeeded) void this.#dialog?.close()
    }
  }

  #setBusy(busy: boolean): void {
    this.#busy = busy
    this.#updateControls()
  }

  #updateControls(): void {
    if (!this.#dialog || !this.#toggle || !this.#applyButton) return
    const canApply = this.#stateStatus === 'ready'
      && (!this.#desiredEnabled
        || (this.#catalogStatus === 'ready'
          && this.#selectedProduct !== null
          && this.#devices.length > 0))

    this.#toggle.disabled = this.#busy || this.#stateStatus !== 'ready'
    this.#applyButton.disabled = this.#busy || !canApply
    const cancelButton = this.#dialog.querySelector<MdOutlinedButton>('#cancel-pif')
    if (cancelButton) cancelButton.disabled = this.#busy
    this.#dialog.toggleAttribute('aria-busy', this.#busy)
    this.#dialog.querySelectorAll<MdRadio>('md-radio').forEach(radio => {
      radio.disabled = this.#busy
    })
    this.#dialog.querySelectorAll<MdOutlinedButton>('.pif-panel-status md-outlined-button').forEach(button => {
      button.disabled = this.#busy
    })

    const label = this.#applyButton.querySelector<HTMLElement>('.pif-apply-label')
    if (label) label.textContent = i18n.t(this.#busy ? 'pif_applying' : 'functional_button_apply')
    const progress = this.#applyButton.querySelector<HTMLElement>('.pif-apply-progress')
    progress?.toggleAttribute('hidden', !this.#busy)
  }
}

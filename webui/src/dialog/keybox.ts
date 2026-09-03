import type { MdDialog, MdFilledButton, MdOutlinedButton } from '@material/web/all'
import { Cli, MAX_KEYBOX_XML_BYTES } from '../cli'
import { i18n } from '../i18n'
import { Snackbar } from '../snackbar/snackbar'
import { isDev } from '../utils/dev'
import { applyDialogAnimation } from './animation'
import './dialog.scss'

export class KeyboxDialog {
  #dialog: MdDialog | null = null
  #fileInput: HTMLInputElement | null = null
  #selectedFile: File | null = null
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
      <input id="keybox-file-input" type="file" accept="*/*" hidden>
      <md-dialog id="keybox-dialog">
        <div slot="headline"></div>
        <div slot="content" class="keybox-dialog-content">
          <div class="keybox-selected-file"></div>
        </div>
        <div slot="actions">
          <md-outlined-button id="cancel-keybox"></md-outlined-button>
          <md-filled-button id="replace-keybox"></md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    const dialog = fragment.querySelector<MdDialog>('#keybox-dialog')!
    const fileInput = fragment.querySelector<HTMLInputElement>('#keybox-file-input')!
    this.#dialog = dialog
    this.#fileInput = fileInput

    fragment.querySelector<HTMLElement>('#keybox-dialog [slot="headline"]')!.textContent =
      i18n.t('replace_keybox_title')

    const cancelButton = fragment.querySelector<MdOutlinedButton>('#cancel-keybox')!
    cancelButton.textContent = i18n.t('functional_button_cancel')
    cancelButton.onclick = () => this.close()
    const replaceButton = fragment.querySelector<MdFilledButton>('#replace-keybox')!
    replaceButton.textContent = i18n.t('functional_button_replace')
    replaceButton.onclick = () => void this.#install()

    fileInput.addEventListener('change', () => this.#handleSelection())
    dialog.addEventListener('closed', () => {
      if (!this.#busy) this.#clearSelection()
    })
    for (const eventName of ['cancel', 'close']) {
      dialog.addEventListener(eventName, event => {
        if (this.#busy) event.preventDefault()
      })
    }
    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  choose(): void {
    if (!this.#fileInput || this.#busy) return
    this.#fileInput.value = ''
    this.#fileInput.click()
  }

  close(): boolean {
    if (this.#busy) return false
    this.#dialog?.close()
    return true
  }

  #handleSelection(): void {
    const file = this.#fileInput?.files?.[0]
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.xml')) {
      this.#snackbar.show(i18n.t('prompt_keybox_xml_required'), false)
      this.#clearSelection()
      return
    }
    if (file.size > MAX_KEYBOX_XML_BYTES) {
      this.#snackbar.show(i18n.t('prompt_keybox_too_large'), false)
      this.#clearSelection()
      return
    }

    this.#selectedFile = file
    const selected = this.#dialog?.querySelector<HTMLElement>('.keybox-selected-file')
    if (selected) selected.textContent = i18n.t('replace_keybox_selected_file', file.name)
    this.#dialog?.show()
  }

  async #install(): Promise<void> {
    const file = this.#selectedFile
    if (!file || this.#busy) return

    this.#setBusy(true)
    let replaced = false
    try {
      const contents = new Uint8Array(await file.arrayBuffer())
      if (contents.byteLength > MAX_KEYBOX_XML_BYTES) {
        throw new Error(i18n.t('prompt_keybox_too_large'))
      }
      if (!isDev()) await this.#cli.installKeybox(contents)
      this.#snackbar.show(i18n.t('prompt_keybox_replaced'))
      replaced = true
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.error('Unable to replace keybox.xml:', error)
      this.#snackbar.show(i18n.t('prompt_keybox_replace_error', detail), false, 6000)
    } finally {
      this.#setBusy(false)
      if (replaced) this.#dialog?.close()
      if (!this.#dialog?.open) this.#clearSelection()
    }
  }

  #setBusy(busy: boolean): void {
    this.#busy = busy
    const cancelButton = this.#dialog?.querySelector<MdOutlinedButton>('#cancel-keybox')
    const replaceButton = this.#dialog?.querySelector<MdFilledButton>('#replace-keybox')
    if (cancelButton) cancelButton.disabled = busy
    if (replaceButton) replaceButton.disabled = busy
  }

  #clearSelection(): void {
    this.#selectedFile = null
    if (this.#fileInput) this.#fileInput.value = ''
  }
}

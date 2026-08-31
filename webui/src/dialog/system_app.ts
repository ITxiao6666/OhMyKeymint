import type { MdDialog, MdFilledButton, MdIconButton, MdOutlinedButton, MdOutlinedTextField } from '@material/web/all'
import { AppList } from '../app_list/app_list'
import { i18n } from '../i18n'
import { applyDialogAnimation } from './animation'
import './dialog.scss'

type CheckboxElement = HTMLElement & { checked: boolean }

export class SystemAppDialog {
  #dialog: MdDialog | null = null
  readonly #appList: AppList

  constructor(appList: AppList) {
    this.#appList = appList
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="system-app-dialog">
        <div slot="headline">
          <span id="system-app-title"></span>
          <md-outlined-text-field id="system-app-search">
            <md-icon slot="leading-icon">search</md-icon>
            <md-icon-button id="system-app-search-close" slot="trailing-icon" style="display:none">
              <md-icon>close</md-icon>
            </md-icon-button>
          </md-outlined-text-field>
        </div>
        <div slot="content"><div id="system-app-list"></div></div>
        <div slot="actions">
          <md-outlined-button id="cancel-system-app"></md-outlined-button>
          <md-filled-button id="save-system-app"></md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#system-app-dialog')

    fragment.querySelector<HTMLElement>('#system-app-title')!.textContent = i18n.t('add_system_app_title')
    const searchField = fragment.querySelector<MdOutlinedTextField>('#system-app-search')!
    searchField.placeholder = i18n.t('search_bar_search_placeholder')
    const searchClose = fragment.querySelector<MdIconButton>('#system-app-search-close')!
    searchClose.title = i18n.t('functional_button_close')

    searchField.addEventListener('input', () => {
      this.#filterList(searchField.value)
      searchClose.style.display = searchField.value ? '' : 'none'
    })
    searchClose.onclick = () => {
      searchField.value = ''
      this.#filterList('')
      searchClose.style.display = 'none'
      searchField.focus()
    }

    const cancelButton = fragment.querySelector<MdOutlinedButton>('#cancel-system-app')!
    cancelButton.textContent = i18n.t('functional_button_cancel')
    cancelButton.onclick = () => this.close()
    const saveButton = fragment.querySelector<MdFilledButton>('#save-system-app')!
    saveButton.textContent = i18n.t('functional_button_save')
    saveButton.onclick = () => void this.#save()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  show(): void {
    const container = this.#dialog?.querySelector<HTMLElement>('#system-app-list')
    if (container) this.#appList.renderSystemAppList(container)

    const searchField = this.#dialog?.querySelector<MdOutlinedTextField>('#system-app-search')
    if (searchField) searchField.value = ''
    const searchClose = this.#dialog?.querySelector<MdIconButton>('#system-app-search-close')
    if (searchClose) searchClose.style.display = 'none'
    this.#dialog?.show()
  }

  close(): void {
    this.#dialog?.close()
  }

  #filterList(query: string): void {
    const list = this.#dialog?.querySelector<HTMLElement>('#system-app-list')
    if (!list) return
    const normalized = query.toLowerCase().trim()
    list.querySelectorAll<HTMLElement>('.card-box').forEach(card => {
      const text = card.textContent?.toLowerCase() ?? ''
      card.style.display = !normalized || text.includes(normalized) ? '' : 'none'
    })
  }

  async #save(): Promise<void> {
    const list = this.#dialog?.querySelector<HTMLElement>('#system-app-list')
    if (!list) return

    const checkedApps: string[] = []
    list.querySelectorAll<HTMLElement>('.card').forEach(card => {
      const checkbox = card.querySelector<CheckboxElement>('md-checkbox')
      if (checkbox?.checked && card.dataset.package) checkedApps.push(card.dataset.package)
    })

    await this.#appList.saveSystemAppSelection(checkedApps)
    this.close()
  }
}

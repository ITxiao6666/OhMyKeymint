import type { MdDialog, MdFab, MdIconButton, MdOutlinedTextField } from '@material/web/all'
import '@material/web/button/filled-button.js'
import '@material/web/button/outlined-button.js'
import '@material/web/checkbox/checkbox.js'
import '@material/web/dialog/dialog.js'
import '@material/web/divider/divider.js'
import '@material/web/fab/fab.js'
import '@material/web/icon/icon.js'
import '@material/web/iconbutton/filled-tonal-icon-button.js'
import '@material/web/iconbutton/icon-button.js'
import '@material/web/menu/menu-item.js'
import '@material/web/menu/menu.js'
import '@material/web/menu/sub-menu.js'
import '@material/web/progress/circular-progress.js'
import '@material/web/ripple/ripple.js'
import '@material/web/textfield/outlined-text-field.js'
import { AppList } from './app_list/app_list'
import { Cli } from './cli'
import { ConfigOhMyKeyMint } from './config_ohmykeymint'
import { KeyboxDialog } from './dialog/keybox'
import { SystemAppDialog } from './dialog/system_app'
import { History } from './history'
import { i18n } from './i18n'
import { Keybind } from './keybind'
import { MainMenu } from './main_menu/main_menu'
import { SearchBar } from './search_bar/search_bar'
import { Snackbar } from './snackbar/snackbar'
import './style.scss'

await i18n.init()

const root = document.querySelector<HTMLDivElement>('#app')!
root.innerHTML = /* html */ `
  <section class="header">
    <div id="title" class="search-hide">Oh My Keymint</div>
    <div class="spacer"></div>
    <md-icon-button id="search-button" class="search-hide"><md-icon>search</md-icon></md-icon-button>
    <md-outlined-text-field class="search-bar hide">
      <md-icon-button slot="trailing-icon" id="search-close"><md-icon>close</md-icon></md-icon-button>
    </md-outlined-text-field>
    <div class="main-menu">
      <md-icon-button id="menu-button"><md-icon>more_vert</md-icon></md-icon-button>
    </div>
  </section>

  <section class="body-content">
    <div class="app-list">
      <div class="loading"><md-circular-progress indeterminate></md-circular-progress></div>
    </div>
    <div class="bottom-safe-inset"></div>
  </section>

  <section class="floating-content fab-hide">
    <div class="snackbar hide"><div class="snackbar-text"></div></div>
    <div class="fab-container">
      <md-fab variant="primary" class="fab fab-hide" id="save">
        <md-icon slot="icon">edit_note</md-icon>
      </md-fab>
    </div>
  </section>

  <section class="dialog-content"></section>
`

const cli = new Cli()
const config = new ConfigOhMyKeyMint(cli)
const appList = new AppList(config)
const snackbar = new Snackbar()
const history = new History()
const keybind = new Keybind()

const appListContainer = root.querySelector<HTMLElement>('.app-list')!
const saveFab = root.querySelector<MdFab>('#save')!
saveFab.label = i18n.t('functional_button_save')
setSaveEnabled(false)

const searchField = root.querySelector<MdOutlinedTextField>('.search-bar')!
searchField.placeholder = i18n.t('search_bar_search_placeholder')
const searchButton = root.querySelector<MdIconButton>('#search-button')!
searchButton.title = i18n.t('search_bar_search_placeholder')

const searchBar = new SearchBar(history)
searchBar.init(
  searchField,
  root.querySelectorAll<HTMLElement>('.search-hide'),
  appListContainer,
)
searchButton.onclick = () => searchBar.show()

async function reloadAppList(scrollToTop: boolean): Promise<void> {
  setSaveEnabled(false)
  let readError: unknown = null

  try {
    await config.read()
  } catch (error) {
    readError = error
  }

  await appList.fetch()
  appList.syncSystemAppsWithConfig()
  appList.renderAppList(appListContainer)
  setSaveEnabled(config.isWritable)
  float(false)

  if (scrollToTop) window.scrollTo(0, 0)
  if (readError !== null) {
    console.error('Unable to load the OMK scoop list:', readError)
    snackbar.show(i18n.t('prompt_load_error'), false, 6000)
  }
}

async function saveTarget(): Promise<void> {
  if (!config.isWritable) {
    snackbar.show(i18n.t('prompt_load_error'), false, 6000)
    return
  }

  setSaveEnabled(false)
  try {
    await appList.save()
    snackbar.show(i18n.t('prompt_saved_target'))
  } catch (error) {
    console.error('Unable to save the OMK scoop list:', error)
    snackbar.show(i18n.t('prompt_save_error'), false)
  } finally {
    setSaveEnabled(config.isWritable)
  }
}

saveFab.onclick = () => void saveTarget()

const mainMenu = new MainMenu()
const mainMenuContainer = root.querySelector<HTMLElement>('.main-menu')!
mainMenu.appendTo(mainMenuContainer)
mainMenu.on('menu-open', () => { appList.menuOpen = true })
mainMenu.on('menu-close', () => { appList.menuOpen = false })
mainMenu.on('menu-refresh', () => void reloadAppList(true))
mainMenu.on('menu-select-all', () => appList.selectAll())
mainMenu.on('menu-deselect-all', () => appList.deselectAll())

const systemAppDialog = new SystemAppDialog(appList)
const dialogContent = root.querySelector<HTMLElement>('.dialog-content')!
dialogContent.appendChild(systemAppDialog.getElement())
systemAppDialog.initAnimation()
mainMenu.on('menu-add-system-app', () => systemAppDialog.show())

const keyboxDialog = new KeyboxDialog(cli, snackbar)
dialogContent.appendChild(keyboxDialog.getElement())
keyboxDialog.initAnimation()
mainMenu.on('menu-install-keybox', () => keyboxDialog.choose())

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
    dialog.close()
  }
  dialog.addEventListener('open', () => history.push(id, closeFromHistory))
  dialog.addEventListener('closed', () => history.consume(id))
})

keybind.on('keybind-select-all', () => appList.selectAll())
keybind.on('keybind-deselect-all', () => appList.deselectAll())
keybind.on('keybind-search', () => searchBar.show())
keybind.on('keybind-save', () => void saveTarget())
keybind.on('keybind-esc', () => history.back())

function float(hide: boolean): void {
  root.querySelectorAll('.floating-content, .fab').forEach(element => {
    element.classList.toggle('fab-hide', hide)
  })
}

function setSaveEnabled(enabled: boolean): void {
  saveFab.toggleAttribute('disabled', !enabled)
  saveFab.setAttribute('aria-disabled', String(!enabled))
  saveFab.tabIndex = enabled ? 0 : -1
}

let lastScrollY = window.scrollY
window.onscroll = () => {
  root.querySelectorAll('md-menu').forEach(menu => menu.close())
  float(window.scrollY > lastScrollY && window.scrollY > 48)
  root.querySelector('.header')?.classList.toggle('scroll', window.scrollY > 10)
  lastScrollY = window.scrollY
}

await reloadAppList(false)

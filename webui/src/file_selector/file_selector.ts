import { exec } from 'kernelsu-alt'
import type { MdDialog, MdIconButton, MdOutlinedButton } from '@material/web/all'
import { i18n } from '../i18n'
import { MAX_KEYBOX_XML_BYTES } from '../cli'
import { applyDialogAnimation } from '../dialog/animation'
import './file_selector.scss'

const STORAGE_ROOT = '/storage/emulated/0'
const INITIAL_PATH = `${STORAGE_ROOT}/Download`
const MAX_LIST_ENTRIES = 512
const MAX_LIST_OUTPUT_BYTES = 256 * 1024
const MAX_ERROR_LENGTH = 512
// Android WebView can dispatch focus/visibility events before the file input's
// change event. Keep the input alive long enough for slower storage providers
// (for example MT Manager) to publish the selected URI.
const SYSTEM_PICKER_RETURN_GRACE_MS = 2000

interface FileEntry {
  name: string
  isDirectory: boolean
}

export interface SelectedFile {
  name: string
  contents: Uint8Array
}

interface PendingSelection {
  token: number
  resolve: (value: SelectedFile | null) => void
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

function commandError(errno: number, stderr: string): Error {
  const detail = stderr.trim().replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, MAX_ERROR_LENGTH)
  return new Error(detail || `storage command exited with code ${errno}`)
}

function isSafeEntryName(name: string): boolean {
  return name.length > 0
    && name !== '.'
    && name !== '..'
    && !/[\\/\u0000-\u001f\u007f]/.test(name)
}

function hasFileExtension(name: string, extension: string): boolean {
  return name.toLowerCase().endsWith(`.${extension}`)
}

function joinStoragePath(parent: string, name: string): string | null {
  if (!isSafeEntryName(name)) return null
  if (parent !== STORAGE_ROOT && !parent.startsWith(`${STORAGE_ROOT}/`)) return null
  const path = `${parent}/${name}`
  if (!path.startsWith(`${STORAGE_ROOT}/`)) return null
  return path
}

function decodeBase64(value: string, maxBytes: number): Uint8Array {
  const normalized = value.replace(/[\t\n\r ]/g, '')
  const maxEncodedLength = Math.ceil(maxBytes / 3) * 4 + 16
  if (normalized.length > maxEncodedLength || normalized.length % 4 !== 0
      || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('storage command returned invalid data')
  }

  let binary: string
  try {
    binary = atob(normalized)
  } catch {
    throw new Error('storage command returned invalid data')
  }
  if (binary.length > maxBytes) throw new Error('selected file exceeds the size limit')

  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function parseListing(value: string, extension: string): FileEntry[] {
  const bytes = decodeBase64(value, MAX_LIST_OUTPUT_BYTES)
  const entries: FileEntry[] = []
  let offset = 0
  let terminated = false

  while (offset < bytes.length) {
    const kind = bytes[offset++]
    if (offset >= bytes.length || bytes[offset++] !== 0) {
      throw new Error('storage command returned malformed entries')
    }
    if (kind === 0x78) { // x: the shell found more entries than the UI limit.
      throw new Error('folder contains too many entries')
    }
    if (kind === 0x7a) { // z: successful end-of-list marker.
      if (offset !== bytes.length) throw new Error('storage command returned malformed entries')
      terminated = true
      break
    }
    if (kind !== 0x64 && kind !== 0x66) {
      throw new Error('storage command returned malformed entries')
    }

    const end = bytes.indexOf(0, offset)
    if (end < 0) throw new Error('storage command returned malformed entries')
    let name: string
    try {
      name = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(offset, end))
    } catch {
      throw new Error('storage command returned an invalid file name')
    }
    if (!isSafeEntryName(name)) throw new Error('storage command returned an invalid file name')
    if (kind === 0x66 && !hasFileExtension(name, extension)) {
      throw new Error('storage command returned an invalid file')
    }
    entries.push({ name, isDirectory: kind === 0x64 })
    if (entries.length > MAX_LIST_ENTRIES) throw new Error('folder contains too many entries')
    offset = end + 1
  }

  if (!terminated) throw new Error('storage command returned an incomplete listing')
  entries.sort((left, right) => {
    if (left.isDirectory !== right.isDirectory) return left.isDirectory ? -1 : 1
    return left.name.localeCompare(right.name, undefined, { sensitivity: 'base' })
  })
  return entries
}

function shellExtensionPattern(extension: string): string {
  return extension.split('').map(character => {
    if (/[a-z]/.test(character)) return `[${character}${character.toUpperCase()}]`
    if (/[A-Z]/.test(character)) return `[${character.toLowerCase()}${character}]`
    return character
  }).join('')
}

function buildListCommand(path: string, extension: string): string {
  const extensionPattern = shellExtensionPattern(extension)
  const script = [
    `root=${shellQuote(STORAGE_ROOT)}`,
    `target=${shellQuote(path)}`,
    'case "$target" in',
    '  "$root"|"$root"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    'if command -v realpath >/dev/null 2>&1; then',
    '  root_real=$(realpath "$root" 2>/dev/null) || exit 1',
    '  resolved=$(realpath "$target" 2>/dev/null) || exit 1',
    'else',
    '  root_real=$(readlink -f "$root" 2>/dev/null) || exit 1',
    '  resolved=$(readlink -f "$target" 2>/dev/null) || exit 1',
    'fi',
    'case "$resolved" in',
    '  "$root_real"|"$root_real"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    '[ -d "$resolved" ] || exit 1',
    'count=0',
    'for entry in "$resolved"/*; do',
    `  [ "$count" -le ${MAX_LIST_ENTRIES} ] || break`,
    '  [ -e "$entry" ] || continue',
    '  [ -L "$entry" ] && continue',
    '  name=$' + '{entry##*/}',
    '  if [ -d "$entry" ]; then',
    String.raw`    printf '%s\000%s\000' d "$name"`,
    '  elif [ -f "$entry" ]; then',
    '    case "$name" in',
    `      *.${extensionPattern}) printf '%s\\000%s\\000' f "$name" ;;`,
    '      *) continue ;;',
    '    esac',
    '  else',
    '    continue',
    '  fi',
    '  count=$((count + 1))',
    'done',
    String.raw`if [ "$count" -gt ${MAX_LIST_ENTRIES} ]; then printf 'x\000'; else printf 'z\000'; fi`,
  ].join('\n')
  const command = `command -v base64 >/dev/null 2>&1 && command -v tr >/dev/null 2>&1 || exit 127\n{\n${script}\n} | base64 | tr -d '\\r\\n'`
  return `/system/bin/sh -c ${shellQuote(command)}`
}

function buildReadCommand(path: string, maxBytes: number): string {
  const script = [
    `root=${shellQuote(STORAGE_ROOT)}`,
    `target=${shellQuote(path)}`,
    `limit=${shellQuote(String(maxBytes))}`,
    'command -v head >/dev/null 2>&1 || exit 127',
    'command -v base64 >/dev/null 2>&1 || exit 127',
    'command -v tr >/dev/null 2>&1 || exit 127',
    'case "$target" in',
    '  "$root"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    '[ -L "$target" ] && exit 1',
    'if command -v realpath >/dev/null 2>&1; then',
    '  root_real=$(realpath "$root" 2>/dev/null) || exit 1',
    '  resolved=$(realpath "$target" 2>/dev/null) || exit 1',
    'else',
    '  root_real=$(readlink -f "$root" 2>/dev/null) || exit 1',
    '  resolved=$(readlink -f "$target" 2>/dev/null) || exit 1',
    'fi',
    'case "$resolved" in',
    '  "$root_real"/*) ;;',
    '  *) exit 2 ;;',
    'esac',
    '[ -f "$resolved" ] || exit 1',
    'bytes=$(wc -c < "$resolved") || exit 1',
    'bytes=${bytes##* }',
    'case "$bytes" in',
    '  ""|*[!0-9]*) exit 1 ;;',
    'esac',
    '[ "$bytes" -le "$limit" ] || exit 3',
    'limit_plus_one=$((limit + 1))',
    'head -c "$limit_plus_one" "$resolved" | base64 | tr -d \'\\r\\n\'',
  ].join('\n')
  return `/system/bin/sh -c ${shellQuote(script)}`
}

export class FileSelector {
  #dialog: MdDialog | null = null
  #fileList: HTMLElement | null = null
  #currentPathElement: HTMLElement | null = null
  #backButton: MdIconButton | null = null
  #systemButton: MdIconButton | null = null
  #closeButton: MdOutlinedButton | null = null
  #systemInput: HTMLInputElement | null = null
  #systemInputCleanup: (() => void) | null = null
  #systemPickerActive = false
  #currentPath = STORAGE_ROOT
  #pathStack: string[] = [STORAGE_ROOT]
  #extension = 'xml'
  #maxBytes = MAX_KEYBOX_XML_BYTES
  #generation = 0
  #requestGeneration = 0
  #pending: PendingSelection | null = null
  #dialogOpening = false
  #dialogOpeningToken: number | null = null
  #dialogClosing = false
  #dialogClosePromise: Promise<void> | null = null
  #dialogCloseResolve: (() => void) | null = null

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="file-selector-dialog" class="file-selector-dialog">
        <div slot="headline" class="file-selector-headline">
          <md-icon-button class="back-button" flip-icon-in-rtl="true">
            <md-icon>arrow_back</md-icon>
          </md-icon-button>
          <div class="current-path" dir="ltr"></div>
        </div>
        <div slot="content" class="file-selector-content">
          <div class="file-list" role="list"></div>
        </div>
        <div slot="actions">
          <md-icon-button class="open-system-file">
            <md-icon>folder_open</md-icon>
          </md-icon-button>
          <div class="selector-actions-spacer"></div>
          <md-outlined-button class="close-selector"></md-outlined-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#file-selector-dialog')
    this.#fileList = fragment.querySelector<HTMLElement>('.file-list')
    this.#currentPathElement = fragment.querySelector<HTMLElement>('.current-path')
    this.#backButton = fragment.querySelector<MdIconButton>('.back-button')
    this.#systemButton = fragment.querySelector<MdIconButton>('.open-system-file')
    this.#closeButton = fragment.querySelector<MdOutlinedButton>('.close-selector')

    this.#currentPathElement?.setAttribute('aria-label', i18n.t('replace_keybox_storage_root'))

    if (this.#backButton) {
      this.#backButton.title = i18n.t('replace_keybox_storage_parent')
      this.#backButton.setAttribute('aria-label', i18n.t('replace_keybox_storage_parent'))
      this.#backButton.onclick = () => this.#navigateBack()
    }
    if (this.#systemButton) {
      this.#systemButton.title = i18n.t('replace_keybox_open_system')
      this.#systemButton.setAttribute('aria-label', i18n.t('replace_keybox_open_system'))
      this.#systemButton.onclick = () => this.#openSystemPicker()
    }
    if (this.#closeButton) {
      this.#closeButton.textContent = i18n.t('functional_button_cancel')
      this.#closeButton.onclick = () => this.close()
    }
    this.#dialog?.addEventListener('close', () => {
      // Scrim/Escape closes are initiated by MdDialog itself. Track them so a
      // new selector request can wait for the same closing animation.
      this.#dialogClosing = true
      this.#trackDialogClose()
    })
    this.#dialog?.addEventListener('closed', () => {
      this.#dialogOpening = false
      this.#dialogOpeningToken = null
      this.#dialogClosing = false
      this.#resolveDialogClose()
      if (this.#pending !== null) this.#finish(null)
      this.#removeSystemInput()
    })
    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  async getFileContent(extension: string, maxBytes = MAX_KEYBOX_XML_BYTES): Promise<SelectedFile | null> {
    const normalizedExtension = extension.trim().replace(/^\./, '').toLowerCase()
    if (!/^[a-z0-9]{1,16}$/.test(normalizedExtension)) {
      return Promise.reject(new Error('Invalid file extension'))
    }
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_KEYBOX_XML_BYTES) {
      return Promise.reject(new Error('Invalid file size limit'))
    }

    // Several callers can enter while the previous dialog is still closing.
    // Re-check after every awaited close so a waiter cannot overwrite a
    // request that resumed just before it; superseded promises must resolve.
    while (true) {
      if (this.#pending !== null) this.#finish(null)
      const closePromise = this.#dialogClosePromise
      if (closePromise === null) break
      await closePromise
    }

    this.#removeSystemInput()
    this.#extension = normalizedExtension
    this.#maxBytes = maxBytes
    this.#currentPath = INITIAL_PATH
    // Start in Download, but keep the shared-storage root in the stack so
    // users can navigate back and choose a keybox from another folder.
    this.#pathStack = [STORAGE_ROOT, INITIAL_PATH]
    const token = ++this.#generation
    const promise = new Promise<SelectedFile | null>(resolve => {
      this.#pending = { token, resolve }
    })

    if (!this.#dialog) {
      this.#finish(null)
      return promise
    }
    this.#renderLoading()
    void this.#showDialog(token)
    void this.#loadInitialPath(token)
    return promise
  }

  close(): boolean {
    if (this.#pending !== null) this.#finish(null)
    else void this.#requestDialogClose()
    return true
  }

  async #showDialog(token: number): Promise<void> {
    const closePromise = this.#dialogClosePromise
    if (closePromise !== null) await closePromise
    if (!this.#isActive(token) || this.#dialog === null) return

    this.#dialogOpening = true
    this.#dialogOpeningToken = token
    try {
      await this.#dialog.show()
    } catch (error) {
      if (this.#isActive(token)) {
        console.error('Unable to open the shared-storage file selector:', error)
        this.#finish(null)
      }
    } finally {
      if (this.#dialogOpeningToken === token) {
        this.#dialogOpening = false
        this.#dialogOpeningToken = null
      }
    }
  }

  async #loadInitialPath(token: number): Promise<void> {
    if (await this.#listDirectory(INITIAL_PATH, token)) return
    if (!this.#isActive(token)) return

    this.#currentPath = STORAGE_ROOT
    this.#pathStack = [STORAGE_ROOT]
    await this.#listDirectory(STORAGE_ROOT, token)
  }

  async #listDirectory(path: string, token: number): Promise<boolean> {
    if (!this.#isActive(token)) return false
    const request = ++this.#requestGeneration
    this.#renderLoading()
    try {
      const result = await exec(buildListCommand(path, this.#extension))
      if (!this.#isRequestActive(token, request)) return false
      if (result.errno !== 0) throw commandError(result.errno, result.stderr)
      const entries = parseListing(result.stdout, this.#extension)
      if (!this.#isRequestActive(token, request)) return false
      this.#renderEntries(entries, token)
      return true
    } catch (error) {
      if (this.#isActive(token)) {
        console.error('Unable to list shared-storage files:', error)
        this.#renderStatus(i18n.t('replace_keybox_storage_error'))
      }
      return false
    }
  }

  #renderLoading(): void {
    if (!this.#fileList) return
    this.#fileList.replaceChildren()
    const status = document.createElement('div')
    status.className = 'file-selector-status'
    status.textContent = i18n.t('replace_keybox_storage_loading')
    this.#fileList.appendChild(status)
    this.#setInteractive(false)
    this.#updatePathLabel()
  }

  #renderStatus(message: string): void {
    if (!this.#fileList) return
    this.#fileList.replaceChildren()
    const status = document.createElement('div')
    status.className = 'file-selector-status'
    status.textContent = message
    this.#fileList.appendChild(status)
    this.#setInteractive(true)
    this.#updatePathLabel()
  }

  #renderEntries(entries: FileEntry[], token: number): void {
    if (!this.#fileList) return
    this.#fileList.replaceChildren()
    if (entries.length === 0) {
      const status = document.createElement('div')
      status.className = 'file-selector-status'
      status.textContent = i18n.t('replace_keybox_storage_empty')
      this.#fileList.appendChild(status)
    }

    if (this.#pathStack.length > 1) {
      this.#fileList.appendChild(this.#createEntryElement(
        i18n.t('replace_keybox_storage_parent'), true, () => this.#navigateBack(),
      ))
    }
    for (const entry of entries) {
      const path = joinStoragePath(this.#currentPath, entry.name)
      if (path === null) continue
      this.#fileList.appendChild(this.#createEntryElement(entry.name, entry.isDirectory, () => {
        if (!this.#isActive(token)) return
        if (entry.isDirectory) {
          this.#currentPath = path
          this.#pathStack.push(path)
          void this.#listDirectory(path, token)
        } else {
          void this.#readLocalFile(path, entry.name, token)
        }
      }))
    }
    this.#setInteractive(true)
    this.#updatePathLabel()
  }

  #createEntryElement(label: string, isDirectory: boolean, callback: () => void): HTMLElement {
    const element = document.createElement('div')
    element.className = 'file-item'
    element.setAttribute('role', 'button')
    element.tabIndex = 0

    const icon = document.createElement('md-icon')
    icon.textContent = isDirectory ? 'folder' : 'description'
    const text = document.createElement('span')
    text.textContent = label
    const ripple = document.createElement('md-ripple')
    element.append(ripple, icon, text)
    element.onclick = callback
    element.onkeydown = event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        callback()
      }
    }
    return element
  }

  async #readLocalFile(path: string, name: string, token: number): Promise<void> {
    if (!this.#isActive(token)) return
    const request = ++this.#requestGeneration
    this.#renderLoading()
    try {
      const result = await exec(buildReadCommand(path, this.#maxBytes))
      if (!this.#isRequestActive(token, request)) return
      if (result.errno !== 0) {
        if (result.errno === 3) throw new Error('selected file exceeds the size limit')
        throw commandError(result.errno, result.stderr)
      }
      const contents = decodeBase64(result.stdout, this.#maxBytes)
      this.#finish({ name, contents })
    } catch (error) {
      if (!this.#isActive(token)) return
      console.error('Unable to read shared-storage file:', error)
      this.#renderStatus(i18n.t('replace_keybox_storage_error'))
    }
  }

  #navigateBack(): void {
    const pending = this.#pending
    if (pending === null || this.#pathStack.length <= 1) return
    this.#pathStack.pop()
    this.#currentPath = this.#pathStack[this.#pathStack.length - 1] ?? STORAGE_ROOT
    void this.#listDirectory(this.#currentPath, pending.token)
  }

  #openSystemPicker(): void {
    const pending = this.#pending
    if (pending === null || this.#systemPickerActive || this.#systemInput !== null) return

    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '*/*'
    input.setAttribute('aria-hidden', 'true')
    input.style.position = 'fixed'
    input.style.width = '1px'
    input.style.height = '1px'
    input.style.opacity = '0'
    input.style.pointerEvents = 'none'
    this.#systemInput = input
    this.#systemPickerActive = true

    let pickerWasBackgrounded = false
    let returnCleanupTimer: number | null = null
    let cleaned = false
    const clearReturnCleanupTimer = (): void => {
      if (returnCleanupTimer === null) return
      window.clearTimeout(returnCleanupTimer)
      returnCleanupTimer = null
    }
    const cleanup = (): void => {
      if (cleaned) return
      cleaned = true
      clearReturnCleanupTimer()
      window.removeEventListener('blur', onBlur)
      window.removeEventListener('focus', onFocus)
      window.removeEventListener('pageshow', onPageShow)
      window.removeEventListener('pagehide', onPageHide)
      document.removeEventListener('visibilitychange', onVisibilityChange)
      // A stale callback from an older picker must not clear the state of a
      // newer picker that has already taken ownership of these fields.
      const ownsInput = this.#systemInput === input && this.#systemInputCleanup === cleanup
      if (ownsInput) {
        this.#systemInput = null
        this.#systemInputCleanup = null
        this.#systemPickerActive = false
        if (this.#pending !== null) this.#setInteractive(true)
      }
      input.remove()
    }

    const handleSelectedFile = (): void => {
      if (cleaned) return
      clearReturnCleanupTimer()
      const file = input.files?.[0] ?? null
      if (file === null) {
        cleanup()
        return
      }
      // Keep the input attached until the File has been read. Some Android
      // providers expose a temporary URI whose grant lasts for the chooser
      // input's lifetime.
      void this.#handleSystemFile(file, pending.token).then(cleanup, cleanup)
    }

    const cleanupAfterReturn = (): void => {
      returnCleanupTimer = null
      if (cleaned) return
      // Some WebViews expose the file list before dispatching `change`.
      // Process it here rather than removing the input and losing the event.
      if (input.files?.[0] !== undefined) handleSelectedFile()
      else cleanup()
    }

    const scheduleReturnCleanup = (): void => {
      if (cleaned || !pickerWasBackgrounded) return
      clearReturnCleanupTimer()
      returnCleanupTimer = window.setTimeout(
        cleanupAfterReturn,
        SYSTEM_PICKER_RETURN_GRACE_MS,
      )
    }

    const onBlur = (): void => {
      pickerWasBackgrounded = true
    }
    const onFocus = (): void => {
      scheduleReturnCleanup()
    }
    const onPageHide = (): void => {
      pickerWasBackgrounded = true
    }
    const onPageShow = (): void => {
      scheduleReturnCleanup()
    }
    const onVisibilityChange = (): void => {
      if (document.visibilityState === 'hidden') pickerWasBackgrounded = true
      else scheduleReturnCleanup()
    }

    this.#systemInputCleanup = cleanup
    input.addEventListener('cancel', cleanup, { once: true })
    input.addEventListener('change', handleSelectedFile, { once: true })
    document.body.appendChild(input)
    window.addEventListener('blur', onBlur)
    window.addEventListener('focus', onFocus)
    window.addEventListener('pageshow', onPageShow)
    window.addEventListener('pagehide', onPageHide)
    document.addEventListener('visibilitychange', onVisibilityChange)
    try {
      input.click()
    } catch (error) {
      cleanup()
      console.error('Unable to open the system file picker:', error)
      this.#renderStatus(i18n.t('replace_keybox_storage_error'))
    }
  }

  async #handleSystemFile(file: File, token: number): Promise<void> {
    if (!this.#isActive(token)) return
    const request = ++this.#requestGeneration
    if (!hasFileExtension(file.name, this.#extension)) {
      this.#renderStatus(i18n.t('prompt_keybox_xml_required'))
      return
    }
    if (file.size > this.#maxBytes) {
      this.#renderStatus(i18n.t('prompt_keybox_too_large'))
      return
    }

    this.#renderLoading()
    try {
      const contents = new Uint8Array(await file.slice(0, this.#maxBytes + 1).arrayBuffer())
      if (!this.#isRequestActive(token, request)) return
      if (contents.byteLength > this.#maxBytes) {
        this.#renderStatus(i18n.t('prompt_keybox_too_large'))
        return
      }
      this.#finish({ name: file.name, contents })
    } catch (error) {
      if (!this.#isActive(token)) return
      console.error('Unable to read selected file:', error)
      this.#renderStatus(i18n.t('replace_keybox_storage_error'))
    }
  }

  #updatePathLabel(): void {
    if (this.#currentPathElement) this.#currentPathElement.textContent = this.#currentPath
    if (this.#backButton) this.#backButton.disabled = this.#pathStack.length <= 1
  }

  #setInteractive(enabled: boolean): void {
    if (this.#fileList) this.#fileList.classList.toggle('loading', !enabled)
    if (this.#backButton) this.#backButton.disabled = !enabled || this.#pathStack.length <= 1
    if (this.#systemButton) this.#systemButton.disabled = !enabled || this.#systemPickerActive
  }

  #isActive(token: number): boolean {
    return this.#pending?.token === token
  }

  #isRequestActive(token: number, request: number): boolean {
    return this.#isActive(token) && this.#requestGeneration === request
  }

  #finish(value: SelectedFile | null): void {
    const pending = this.#pending
    if (pending === null) return
    this.#pending = null
    this.#generation += 1
    this.#requestGeneration += 1
    this.#removeSystemInput()
    void this.#requestDialogClose().then(
      () => pending.resolve(value),
      () => pending.resolve(value),
    )
  }

  #trackDialogClose(): Promise<void> {
    if (this.#dialogClosePromise !== null) return this.#dialogClosePromise

    let resolveClose!: () => void
    const promise = new Promise<void>(resolve => { resolveClose = resolve })
    this.#dialogClosePromise = promise
    this.#dialogCloseResolve = resolveClose
    return promise
  }

  #resolveDialogClose(): void {
    const resolveClose = this.#dialogCloseResolve
    this.#dialogCloseResolve = null
    this.#dialogClosePromise = null
    resolveClose?.()
  }

  #requestDialogClose(): Promise<void> {
    const dialog = this.#dialog
    if (dialog === null) return Promise.resolve()
    if (this.#dialogClosing) return this.#trackDialogClose()
    if (!dialog.open && !this.#dialogOpening) return Promise.resolve()

    this.#dialogClosing = true
    const tracked = this.#trackDialogClose()
    let closePromise: Promise<void>
    try {
      closePromise = Promise.resolve(dialog.close())
    } catch (error) {
      console.error('Unable to close the shared-storage file selector:', error)
      this.#dialogClosing = false
      this.#resolveDialogClose()
      return Promise.resolve()
    }

    // MdDialog does not emit `closed` when a pending `show()` is cancelled
    // before the native dialog opens. Its close Promise still settles, so use
    // it as a fallback for that case (and for a prevented close event).
    void closePromise.then(() => {
      if (!this.#dialogClosing) return
      this.#dialogClosing = false
      this.#resolveDialogClose()
    }, () => {
      if (!this.#dialogClosing) return
      this.#dialogClosing = false
      this.#resolveDialogClose()
    })
    return tracked
  }

  #removeSystemInput(): void {
    this.#systemInputCleanup?.()
    this.#systemInputCleanup = null
    const input = this.#systemInput
    this.#systemInput = null
    this.#systemPickerActive = false
    input?.remove()
  }
}

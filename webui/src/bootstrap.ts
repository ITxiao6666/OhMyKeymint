import { isSupported, renderBlockingPage } from './webview/webview'

const root = document.querySelector<HTMLDivElement>('#app')!

if (!isSupported()) {
  root.replaceChildren(renderBlockingPage())
} else {
  try {
    await import('./main')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const errorElement = document.createElement('p')
    errorElement.id = 'load-error'
    errorElement.textContent = `Failed to load app: ${message}`
    root.replaceChildren(errorElement)
  }
}

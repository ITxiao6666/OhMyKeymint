import './webview.scss'

const MIN_ANDROID_WEBVIEW_VERSION = 120

interface NavigatorUAData {
  readonly brands: ReadonlyArray<{ readonly brand: string; readonly version: string }>
}

export function getWebviewVersion(): number | null {
  const brands = (navigator as Navigator & { readonly userAgentData?: NavigatorUAData }).userAgentData?.brands
  if (Array.isArray(brands) && brands.length > 0) {
    const webViewBrand = brands.find(entry => entry.brand === 'Android WebView')
    if (webViewBrand) return Number.parseInt(webViewBrand.version, 10)
  }

  const userAgent = navigator.userAgent
  if (/Android/i.test(userAgent) && /\bwv\b/.test(userAgent)) {
    const match = userAgent.match(/Chrome\/(\d+)/)
    return match ? Number.parseInt(match[1], 10) : 0
  }
  return null
}

export function isSupported(): boolean {
  const version = getWebviewVersion()
  return version === null || version >= MIN_ANDROID_WEBVIEW_VERSION
}

export function renderBlockingPage(): HTMLElement {
  const container = document.createElement('div')
  container.className = 'webview'
  const message = document.createElement('p')
  message.textContent = 'Android System WebView 120 or newer is required.'
  container.appendChild(message)
  return container
}

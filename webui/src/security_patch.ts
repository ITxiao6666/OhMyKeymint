/**
 * The Android Security Bulletin overview is the only network source used by
 * the WebUI.  Keep the URL and parser deliberately narrow: a bulletin date is
 * security-sensitive configuration input, so arbitrary pages or dates must
 * never be accepted.
 */
export const ANDROID_SECURITY_BULLETIN_URL =
  'https://source.android.com/docs/security/bulletin/asb-overview'
/** Official Google mirror used when the primary hostname is unavailable. */
export const ANDROID_SECURITY_BULLETIN_MIRROR_URL =
  'https://source.android.google.cn/docs/security/bulletin/asb-overview?hl=zh-cn'

const OFFICIAL_ORIGINS = new Set([
  'https://source.android.com',
  'https://source.android.google.cn',
])
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024
const ISO_DATE_RE = /\b(\d{4})-(\d{2})-(\d{2})\b/g
const MAIN_BULLETIN_PATH_RE =
  /^\/docs\/security\/bulletin\/(?:20\d{2}\/)?20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[/?#]|$)/

/** Return whether an ISO date is a real Gregorian calendar date. */
export function isSecurityPatchDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  if (match === null) return false

  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return false
  if (year < 2000) return false
  if (month < 1 || month > 12 || day < 1) return false
  const leap = year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0)
  const daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
  return day <= daysInMonth
}

function dateIsNotInFuture(value: string, now: Date): boolean {
  const year = Number(value.slice(0, 4))
  const month = Number(value.slice(5, 7))
  const day = Number(value.slice(8, 10))
  if (![year, month, day].every(Number.isInteger)) return false
  const valueKey = year * 10_000 + month * 100 + day
  const todayKey = now.getFullYear() * 10_000 + (now.getMonth() + 1) * 100 + now.getDate()
  return valueKey <= todayKey
}

function collectDates(text: string, now: Date): string[] {
  const dates: string[] = []
  for (const match of text.matchAll(ISO_DATE_RE)) {
    const value = match[0]
    if (isSecurityPatchDate(value) && dateIsNotInFuture(value, now)) dates.push(value)
  }
  return dates
}

function isOfficialUrl(url: URL): boolean {
  return OFFICIAL_ORIGINS.has(url.origin)
    && url.username === ''
    && url.password === ''
}

/** Return whether a URL is the official Android Security Bulletin overview. */
export function isOfficialSecurityBulletinUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return isOfficialUrl(url)
      && url.pathname === '/docs/security/bulletin/asb-overview'
  } catch {
    return false
  }
}

function isMainBulletinLink(anchor: HTMLAnchorElement): boolean {
  try {
    const url = new URL(anchor.getAttribute('href') ?? '', ANDROID_SECURITY_BULLETIN_URL)
    return isOfficialUrl(url) && MAIN_BULLETIN_PATH_RE.test(url.pathname)
  } catch {
    return false
  }
}

function findBulletinTable(document: Document): HTMLTableElement | null {
  const heading = document.querySelector<HTMLElement>('#bulletins')
  if (heading === null) return null

  // The generated page places an aside between this heading and the table.
  // Keep the search scoped to this section so another product's table cannot
  // become a trusted source if the page layout changes.
  let sibling = heading.nextElementSibling
  while (sibling !== null) {
    if (sibling instanceof HTMLTableElement) return sibling
    const nested = sibling.querySelector<HTMLTableElement>('table')
    if (nested !== null) return nested
    if (/^H[1-2]$/.test(sibling.tagName)) break
    sibling = sibling.nextElementSibling
  }
  return null
}

function patchLevelColumn(table: HTMLTableElement): number {
  const headerRow = table.querySelector('thead tr') ?? table.querySelector('tr')
  if (headerRow === null) throw new Error('Android Security Bulletin table has no header')
  const cells = Array.from(headerRow.children)
  const index = cells.findIndex(cell =>
    isPatchLevelHeader(cell.textContent ?? ''),
  )
  if (index < 0) throw new Error('Android Security Bulletin patch-level column was not found')
  return index
}

function isPatchLevelHeader(value: string): boolean {
  const normalized = value.replace(/[\u0000-\u0020]+/g, '').toLowerCase()
  return normalized.includes('securitypatchlevel')
    || normalized.includes('安全补丁级别')
    || normalized.includes('安全補丁級別')
    || normalized.includes('安全性修補程式等級')
}

/**
 * Parse the main Android Security Bulletin table and return its newest
 * published security-patch level. `now` is injectable to keep the parser
 * deterministic in tests and to exclude a future row accidentally present in
 * a cached page.
 */
export function parseLatestSecurityPatch(html: string, now = new Date()): string {
  if (html.length === 0 || new TextEncoder().encode(html).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error('Android Security Bulletin response is too large')
  }

  const document = new DOMParser().parseFromString(html, 'text/html')
  if (document.querySelector('parsererror') !== null) {
    throw new Error('Android Security Bulletin response is not valid HTML')
  }
  const table = findBulletinTable(document)
  if (table === null) throw new Error('Android Security Bulletin table was not found')

  const column = patchLevelColumn(table)
  const dates: string[] = []
  for (const row of table.querySelectorAll('tr')) {
    const link = Array.from(row.querySelectorAll<HTMLAnchorElement>('a'))
      .find(isMainBulletinLink)
    if (link === undefined) continue

    const cells = Array.from(row.children)
    const source = cells[column]?.textContent ?? ''
    dates.push(...collectDates(source, now))
  }

  const latest = dates.sort().at(-1)
  if (latest === undefined) throw new Error('No published Android security patch date was found')
  return latest
}

/**
 * Download and parse a bulletin supplied by the caller.
 *
 * The WebUI passes the module's native HTTPS downloader from `Cli` here.
 * Keeping the downloader injectable makes the parser easy to test without
 * granting this module a second network implementation or relying on WebView
 * cross-origin access.
 */
export async function fetchLatestSecurityPatch(
  fetchText: () => Promise<string>,
): Promise<string> {
  return parseLatestSecurityPatch(await fetchText())
}

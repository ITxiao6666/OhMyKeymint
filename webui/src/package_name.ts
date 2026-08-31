const PACKAGE_NAME = /^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$/

export function isValidPackageName(value: unknown): value is string {
  return typeof value === 'string'
    && value.length > 0
    && value.length <= 255
    && PACKAGE_NAME.test(value)
}

export function normalizePackageNames(values: unknown): string[] {
  if (!Array.isArray(values) || !values.every(isValidPackageName)) {
    throw new Error('Invalid package list returned by OMK')
  }
  return [...new Set(values)]
}

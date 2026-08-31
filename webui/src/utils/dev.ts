import { isKsuWebui } from 'kernelsu-alt'

export function isDev(): boolean {
  return import.meta.env.DEV && !isKsuWebui()
}

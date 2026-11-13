<script setup lang="ts">
import { computed } from 'vue'
import {
  MiuixBasicComponent,
  MiuixCard,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
  MiuixTopAppBar,
} from 'miuix-vue'
import { Refresh } from 'miuix-vue/icons'
import type {
  DiagnosticsState,
  KeyboxLevel,
  KeyboxRevocationStatus,
  KeyboxSource,
} from '../cli'
import { i18n } from '../i18n'

export type ModuleStatus = 'loading' | 'ready' | 'error'
export type KeyboxStatus = 'loading' | 'bundled' | 'custom' | 'invalid' | 'error'
export type TeeStatus = 'loading' | 'normal' | 'error'

const props = defineProps<{
  keyboxStatus: KeyboxStatus
  keyboxSource: KeyboxSource
  keyboxLevel: KeyboxLevel
  keyboxRevocation: KeyboxRevocationStatus
  diagnostics: DiagnosticsState | null
  diagnosticsStatus: 'loading' | 'ready' | 'error'
  teeStatus: TeeStatus
  securityPatch: string | null
  spoofedDevice: string | null | undefined
}>()

const emit = defineEmits<{
  refreshDiagnostics: []
}>()

function tr(key: string, fallback: string, ...args: unknown[]): string {
  const value = i18n.t(key, ...args)
  if (value !== key) return value
  let index = 0
  return fallback.replace(/%s/g, () => String(args[index++] ?? ''))
}

const keyboxSourceLabel = computed(() => {
  if (props.keyboxStatus === 'loading' || props.keyboxStatus === 'error') return '\u2014'
  if (props.keyboxStatus === 'invalid') return tr('home_keybox_invalid', 'Invalid Keybox')
  if (props.keyboxStatus === 'bundled') return tr('home_keybox_bundled', 'Built-in Keybox')
  switch (props.keyboxSource) {
    case 'google_hardware':
      return tr('home_keybox_hardware', 'Google hardware root certificate')
    case 'google_remote':
      return tr('home_keybox_remote', 'Google remote key provisioning')
    default:
      return tr('home_keybox_unknown', 'Unknown key')
  }
})

const keyboxLevelLabel = computed(() => {
  if (props.keyboxStatus === 'invalid' || props.keyboxStatus === 'error') {
    return tr('home_keybox_level_unknown', 'Unknown')
  }
  if (props.keyboxLevel === 'tee') return tr('home_keybox_tee', 'TEE')
  if (props.keyboxLevel === 'strongbox') return tr('home_keybox_strongbox', 'StrongBox')
  return tr('home_keybox_level_unknown', 'Unknown')
})

const revocationState = computed(() => {
  if (props.keyboxStatus === 'invalid') {
    return {
      label: tr('home_keybox_local_invalid', 'Local validation failed'),
      tone: 'error',
    }
  }
  if (props.keyboxStatus === 'error') {
    return {
      label: tr('home_keybox_revocation_check_failed', 'Check failed'),
      tone: 'error',
    }
  }
  switch (props.keyboxRevocation) {
    case 'checking':
      return { label: tr('home_keybox_status_checking', 'Checking'), tone: 'loading' }
    case 'not_listed':
      return { label: tr('home_keybox_revocation_not_revoked', 'Not revoked'), tone: 'muted' }
    case 'suspended':
    case 'revoked':
      return { label: tr('home_keybox_revocation_revoked', 'Revoked'), tone: 'error' }
    case 'unknown':
      return { label: tr('home_keybox_revocation_check_failed', 'Check failed'), tone: 'error' }
    default:
      return { label: tr('home_keybox_status_not_checked', 'Not checked'), tone: 'muted' }
  }
})

const teeState = computed(() => ({
  loading: { label: tr('home_status_loading', 'Checking'), tone: 'loading' },
  normal: { label: tr('home_tee_normal', 'Normal'), tone: 'muted' },
  error: { label: tr('home_status_error', 'Needs attention'), tone: 'error' },
})[props.teeStatus])

const heroState = computed(() => {
  if (props.diagnosticsStatus === 'error') {
    return { tone: 'error', label: tr('home_status_error', 'Needs attention'), detail: '' }
  }
  const keymint = props.diagnostics?.keymint
  if (!keymint) {
    return { tone: 'loading', label: tr('home_status_loading', 'Checking'), detail: '' }
  }
  const detail = keymint.pid !== null ? `PID ${keymint.pid}` : ''
  if (keymint.status === 'running') {
    return { tone: 'active', label: tr('home_status_running', 'Running'), detail }
  }
  return {
    tone: keymint.status === 'error' ? 'error' : 'stopped',
    label: diagnosticStatusLabel(keymint.status),
    detail,
  }
})

function diagnosticStatusLabel(status: string, hardware = false): string {
  switch (status) {
    case 'running': return tr('home_diag_running', 'Running')
    case 'stopped': return tr('home_diag_stopped', 'Stopped')
    case 'configured': return tr('home_diag_configured', 'Configured')
    case 'disabled': return tr('home_diag_disabled', 'Disabled')
    case 'available': return hardware
      ? tr('home_diag_device_supported', 'Hardware supported')
      : tr('home_diag_available', 'Available')
    case 'unavailable': return hardware
      ? tr('home_diag_device_unsupported', 'Hardware not supported')
      : tr('home_diag_unavailable', 'Not registered')
    case 'error': return tr('home_diag_error', 'Probe failed')
    default: return tr('home_diag_unknown', 'Unknown')
  }
}

// Keep the decorative glyph consistent with the reported state so a failure is
// never drawn with a tick.
const heroGlyph = computed(() => {
  if (heroState.value.tone === 'active') return 'tick'
  if (heroState.value.tone === 'error') return 'alert'
  return 'none'
})

// Rows keep the field name on the left and the current value right-aligned,
// so each line reads as one label/value pair.
const identityRows = computed(() => [

  {
    id: 'keybox',
    label: tr('home_keybox', 'Keybox'),
    value: keyboxSourceLabel.value,
    tone: props.keyboxStatus === 'invalid' ? 'error' : 'default',
  },
  {
    id: 'patch',
    label: tr('home_security_patch', 'Security patch'),
    value: props.securityPatch ?? '\u2014',
    tone: 'default',
  },
  {
    id: 'level',
    label: tr('home_keybox_security_level', 'Security Level'),
    value: keyboxLevelLabel.value,
    tone: 'default',
  },
  {
    id: 'revocation',
    label: tr('home_keybox_revocation', 'Certificate status'),
    value: revocationState.value.label,
    tone: revocationState.value.tone,
  },
  {
    id: 'tee',
    label: tr('home_tee_status', 'TEE status'),
    value: teeState.value.label,
    tone: teeState.value.tone,
  },
  {
    id: 'spoof',
    label: tr('home_spoofed_device', 'Spoofed device fingerprint'),
    value: props.spoofedDevice === null
      ? tr('pif_disabled', 'Disabled')
      : (props.spoofedDevice ?? '\u2014'),
    tone: 'default',
  },
])

</script>

<template>
  <section class="app-page home-page" aria-labelledby="home-title">
    <MiuixTopAppBar title="Oh My Keymint">
      <template #actions>
        <MiuixIconButton
          :disabled="diagnosticsStatus === 'loading'"
          :aria-label="tr('tools_diagnostics_refresh', 'Refresh')"
          @click="emit('refreshDiagnostics')"
        >
          <MiuixProgressIndicator
            v-if="diagnosticsStatus === 'loading'"
            type="circular"
            :size="18"
            :stroke-width="2"
          />
          <MiuixIcon v-else :icon="Refresh" :size="22" />
        </MiuixIconButton>
      </template>
    </MiuixTopAppBar>
    <h1 id="home-title" class="page-large-title">Oh My Keymint</h1>

    <MiuixCard class="status-hero" :data-tone="heroState.tone" press-feedback="none">
      <div class="status-hero__text" role="status" aria-live="polite">
        <strong>{{ heroState.label }}</strong>
        <span>
          {{ tr('home_diag_keymint', 'OMK KeyMint') }}<template v-if="heroState.detail"> · {{ heroState.detail }}</template>
        </span>
      </div>
      <!-- The glyph mirrors the state: a tick only while running, an
           exclamation for a failure, and nothing while the read is pending. -->
      <svg
        v-if="heroGlyph !== 'none'"
        class="status-hero__glyph"
        viewBox="0 0 100 100"
        aria-hidden="true"
      >
        <path
          v-if="heroGlyph === 'tick'"
          d="M18 52 L40 74 L84 26"
          fill="none"
          stroke="currentColor"
          stroke-width="15"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
        <template v-else>
          <path
            d="M50 22 L50 62"
            fill="none"
            stroke="currentColor"
            stroke-width="15"
            stroke-linecap="round"
          />
          <circle cx="50" cy="82" r="8" fill="currentColor" />
        </template>
      </svg>
    </MiuixCard>

    <MiuixCard class="info-card" press-feedback="none">
      <MiuixBasicComponent
        v-for="row in identityRows"
        :key="row.id"
        :title="row.label"
      >
        <template #end>
          <span class="row-value" :data-tone="row.tone">{{ row.value }}</span>
        </template>
      </MiuixBasicComponent>
    </MiuixCard>

  </section>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import {
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixProgressIndicator,
  MiuixTopAppBar,
} from 'miuix-vue'
import { Info } from 'miuix-vue/icons'
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

const serviceRows = computed(() => {
  if (!props.diagnostics) return []
  return [
    { id: 'keymint', label: tr('home_diag_keymint', 'OMK KeyMint'), value: props.diagnostics.keymint },
  ]
})

const hardwareRows = computed(() => {
  if (!props.diagnostics) return []
  return [
    { id: 'tee', label: 'TEE · KeyMint', value: props.diagnostics.tee },
    { id: 'strongbox', label: 'StrongBox · KeyMint', value: props.diagnostics.strongbox },
    { id: 'rkp-tee', label: 'TEE · RKP', value: props.diagnostics.rkp_tee },
    { id: 'rkp-strongbox', label: 'StrongBox · RKP', value: props.diagnostics.rkp_strongbox },
  ]
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

function diagnosticTone(status: string): string {
  return status === 'error' ? 'error' : 'muted'
}

</script>

<template>
  <section class="app-page home-page" aria-labelledby="home-title">
    <MiuixTopAppBar id="home-title" title="Oh My Keymint" />

    <div class="identity-grid" aria-live="polite">
      <MiuixCard class="identity-card" press-feedback="none">
        <div class="identity-field identity-field--primary">
          <span>{{ tr('home_keybox', 'Keybox') }}</span>
          <strong :data-source="keyboxSource">{{ keyboxSourceLabel }}</strong>
        </div>
        <div class="identity-field">
          <span>{{ tr('home_keybox_security_level', 'Security Level') }}</span>
          <strong>{{ keyboxLevelLabel }}</strong>
        </div>
        <div class="identity-field">
          <span>{{ tr('home_keybox_revocation', 'Certificate status') }}</span>
          <strong :data-tone="revocationState.tone">{{ revocationState.label }}</strong>
        </div>
      </MiuixCard>

      <MiuixCard class="identity-card" press-feedback="none">
        <div class="identity-field identity-field--primary">
          <span>{{ tr('home_security_patch', 'Security patch') }}</span>
          <strong>{{ securityPatch ?? '\u2014' }}</strong>
        </div>
        <div class="identity-field">
          <span>{{ tr('home_tee_status', 'TEE status') }}</span>
          <strong :data-tone="teeState.tone">{{ teeState.label }}</strong>
        </div>
        <div class="identity-field">
          <span>{{ tr('home_spoofed_device', 'Spoofed device fingerprint') }}</span>
          <strong>{{ spoofedDevice === null ? tr('pif_disabled', 'Disabled') : (spoofedDevice ?? '\u2014') }}</strong>
        </div>
      </MiuixCard>
    </div>

    <MiuixCard class="diagnostics-card" press-feedback="none">
      <header class="diagnostics-heading">
        <div>
          <h2>{{ tr('home_diagnostics_title', 'Current device status') }}</h2>
        </div>
        <MiuixButton
          type="default"
          class="diagnostics-refresh"
          :disabled="diagnosticsStatus === 'loading'"
          @click="emit('refreshDiagnostics')"
        >
          <MiuixProgressIndicator v-if="diagnosticsStatus === 'loading'" type="circular" :size="16" />
          {{ tr('tools_diagnostics_refresh', 'Refresh') }}
        </MiuixButton>
      </header>
      <div v-if="diagnosticsStatus === 'loading' && !diagnostics" class="diagnostics-empty" role="status">
        <MiuixProgressIndicator type="circular" :size="22" :stroke-width="2" />
        <span>{{ tr('home_status_loading', 'Checking') }}</span>
      </div>
      <div v-else-if="diagnosticsStatus === 'error'" class="diagnostics-empty" role="alert">
        <MiuixIcon :icon="Info" :size="22" />
        <span>{{ tr('home_diagnostics_error', 'Unable to load diagnostics') }}</span>
      </div>
      <dl v-else class="diagnostics-services">
        <div v-for="row in serviceRows" :key="row.id" class="diagnostics-service">
          <dt>{{ row.label }}</dt>
          <dd :data-tone="diagnosticTone(row.value.status)">
            {{ diagnosticStatusLabel(row.value.status) }}
            <small v-if="row.value.pid !== null">PID {{ row.value.pid }}</small>
          </dd>
        </div>
      </dl>

      <dl v-if="diagnostics" class="diagnostics-services diagnostics-services--hardware">
        <div v-for="row in hardwareRows" :key="row.id" class="diagnostics-service">
          <dt>{{ row.label }}</dt>
          <dd :data-tone="row.value.status === 'error' ? 'error' : 'muted'">
            {{ diagnosticStatusLabel(row.value.status, true) }}
            <small v-if="'name' in row.value && row.value.name">
              {{ row.value.name }}<template v-if="row.value.version !== null"> · v{{ row.value.version }}</template>
            </small>
          </dd>
        </div>
      </dl>
    </MiuixCard>

  </section>
</template>

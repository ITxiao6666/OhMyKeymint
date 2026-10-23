<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  MiuixBasicComponent,
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixProgressIndicator,
  MiuixTopAppBar,
} from 'miuix-vue'
import { ExpandMore, Info } from 'miuix-vue/icons'
import type {
  DiagnosticsState,
  KeyboxInspector,
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
  keyboxInspector: KeyboxInspector | null
  diagnostics: DiagnosticsState | null
  diagnosticsStatus: 'loading' | 'ready' | 'error'
  teeStatus: TeeStatus
  securityPatch: string | null
  spoofedDevice: string | null | undefined
}>()

const emit = defineEmits<{
  refreshDiagnostics: []
}>()

const expandedKeyboxChains = ref(new Set<string>())

function toggleKeyboxChain(algorithm: string): void {
  const expanded = new Set(expandedKeyboxChains.value)
  if (expanded.has(algorithm)) expanded.delete(algorithm)
  else expanded.add(algorithm)
  expandedKeyboxChains.value = expanded
}

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

const keyboxChains = computed(() => {
  const inspector = props.keyboxInspector
  if (!inspector) return []
  return [inspector.rsa, inspector.ec]
    .filter((chain): chain is NonNullable<typeof chain> => chain !== null)
    .map(chain => ({
      ...chain,
      certificates: [...chain.certificates].reverse().map(certificate => ({
        ...certificate,
        validFromLabel: certificateDate(certificate.valid_from),
        validUntilLabel: certificateDate(certificate.valid_until),
      })),
    }))
})

const serviceRows = computed(() => {
  if (!props.diagnostics) return []
  return [
    { id: 'keymint', label: tr('home_diag_keymint', 'OMK KeyMint'), value: props.diagnostics.keymint },
    { id: 'soter', label: tr('home_diag_soter', 'Soter'), value: props.diagnostics.soter },
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

// Language selection reloads the WebUI; one formatter serves this view.
const certificateDateFormatter = new Intl.DateTimeFormat(i18n.lang, {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'long',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
})

function certificateDate(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const parts = certificateDateFormatter.formatToParts(date)
  if (i18n.lang.startsWith('zh')) {
    const part = (type: Intl.DateTimeFormatPartTypes): string => parts.find(value => value.type === type)?.value ?? ''
    return `${part('year')}年${date.getUTCMonth() + 1}月${part('day')}日 ${part('hour')}:${part('minute')}:${part('second')} UTC`
  }
  return `${parts.map(part => part.value).join('')} UTC`
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
          <h2>{{ tr('home_diagnostics_title', 'Device diagnostics') }}</h2>
          <span>{{ tr('home_diagnostics_desc', 'Runtime services and installed Keybox details') }}</span>
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
      <p class="diagnostics-muted diagnostics-note">{{ tr('tools_diagnostics_note', 'HAL and RKP checks query registered AIDL services. Availability does not verify hardware-backed attestation or remote provisioning.') }}</p>

      <div class="keybox-inspector">
        <h3>{{ tr('home_keybox_inspector', 'Keybox certificates') }}</h3>
        <p v-if="!keyboxInspector" class="diagnostics-muted">
          {{ tr('home_keybox_inspector_unavailable', 'Certificate details unavailable') }}
        </p>
        <p v-else-if="keyboxChains.length === 0" class="diagnostics-muted">
          {{ tr('home_keybox_inspector_empty', 'No certificate chains found') }}
        </p>
        <div v-else class="keybox-chains">
          <div v-for="chain in keyboxChains" :key="chain.algorithm" class="keybox-chain">
            <MiuixBasicComponent
              :title="chain.algorithm"
              :summary="tr('home_keybox_chain_length', '%s certificates', chain.chain_length)"
              clickable
              :aria-expanded="expandedKeyboxChains.has(chain.algorithm)"
              :aria-controls="`keybox-chain-details-${chain.algorithm}`"
              @click="toggleKeyboxChain(chain.algorithm)"
            >
              <template #end>
                <MiuixIcon
                  class="keybox-chain__expand"
                  :class="{ 'is-expanded': expandedKeyboxChains.has(chain.algorithm) }"
                  :icon="ExpandMore"
                  :size="22"
                />
              </template>
            </MiuixBasicComponent>
            <div
              :id="`keybox-chain-details-${chain.algorithm}`"
              class="keybox-chain__collapse"
              :class="{ 'is-expanded': expandedKeyboxChains.has(chain.algorithm) }"
              :aria-hidden="!expandedKeyboxChains.has(chain.algorithm)"
            >
              <div class="keybox-certificates">
                <article
                  v-for="(certificate, index) in chain.certificates"
                  :key="`${chain.algorithm}-${certificate.serial}-${index}`"
                  class="keybox-certificate"
                >
                  <h4>{{ tr('home_keybox_certificate_number', 'Certificate %s', index + 1) }}</h4>
                  <dl class="keybox-certificate__details">
                    <div>
                      <dt>{{ tr('home_keybox_subject', 'Subject') }}</dt>
                      <dd>{{ certificate.subject }}</dd>
                    </div>
                    <div>
                      <dt>{{ tr('home_keybox_valid_from', 'Not before') }}</dt>
                      <dd>{{ certificate.validFromLabel }}</dd>
                    </div>
                    <div>
                      <dt>{{ tr('home_keybox_valid_until', 'Not after') }}</dt>
                      <dd>{{ certificate.validUntilLabel }}</dd>
                    </div>
                    <div>
                      <dt>{{ tr('home_keybox_serial', 'Serial number') }}</dt>
                      <dd>{{ certificate.serial }}</dd>
                    </div>
                  </dl>
                </article>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MiuixCard>

  </section>
</template>

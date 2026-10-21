<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import {
  MiuixButton,
  MiuixDialog,
  MiuixInput,
  MiuixProgressIndicator,
  MiuixSwitchPreference,
} from 'miuix-vue'
import { Cli, type SoterHalState } from '../cli'
import { afterPaint } from '../app_list/app_list'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

const props = defineProps<{ modelValue: boolean, cli: Cli }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  notify: [message: string, error?: boolean]
}>()

const preview = isDev()
const DEFAULT_RELAY_URL = 'http://110.40.170.96:10886'
const DEFAULT_RELAY_DEVICE_ID = 'device-b-c3f204aa'
const DEFAULT_RELAY_TOKEN = 'aY7kRSDDR6PMmamlKwtgf7mQgr-X5uFd'
const enabled = ref(false)
const remoteEnabled = ref(false)
const appEnabled = ref(false)
const url = ref('')
const token = ref('')
const deviceId = ref('')
const tlsInsecure = ref(false)
const uidMap = ref('')
const soterBetaEnabled = ref(false)
const saved = ref<SoterHalState | null>(null)
const status = ref<'loading' | 'ready' | 'error'>('loading')
const errorMessage = ref('')
const busy = ref(false)
let generation = 0

function tr(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const current = computed<SoterHalState | null>(() => {
  if (!saved.value) return null
  return {
    enabled: enabled.value,
    remote_enabled: remoteEnabled.value,
    url: url.value,
    token: token.value,
    device_id: deviceId.value,
    tls_insecure: tlsInsecure.value,
    uid_map: uidMap.value,
    app_enabled: appEnabled.value,
    app_targets: saved.value.app_targets,
  }
})

const canApply = computed(() => {
  if (preview || busy.value || status.value !== 'ready' || !saved.value) return false
  const state = current.value
  if (!state) return false
  if (state.remote_enabled && (!state.url.trim() || !state.token.trim() || !state.device_id.trim())) return false
  if (state.remote_enabled) {
    try {
      const parsed = new URL(state.url)
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname
          || parsed.username || parsed.password) return false
    } catch { return false }
  }
  if ((state.enabled || state.app_enabled) && soterBetaEnabled.value) return false
  if (state.enabled && state.app_enabled) return false
  return JSON.stringify(state) !== JSON.stringify(saved.value)
})

async function load(): Promise<void> {
  if (!props.modelValue || busy.value) return
  const currentGeneration = ++generation
  status.value = 'loading'
  saved.value = null
  errorMessage.value = ''
  soterBetaEnabled.value = false
  try {
    await afterPaint()
    if (currentGeneration !== generation || !props.modelValue) return
    const [state, betaState] = preview
      ? [{
          enabled: false,
          remote_enabled: false,
          url: DEFAULT_RELAY_URL,
          token: DEFAULT_RELAY_TOKEN,
          device_id: DEFAULT_RELAY_DEVICE_ID,
          tls_insecure: false,
          uid_map: '',
          app_enabled: false,
          app_targets: [],
        }, { enabled: false }]
      : await Promise.all([props.cli.getSoterHal(), props.cli.getSoterBeta()])
    if (currentGeneration !== generation || !props.modelValue) return
    enabled.value = state.enabled
    remoteEnabled.value = state.remote_enabled
    appEnabled.value = state.app_enabled
    url.value = state.url
    token.value = state.token
    deviceId.value = state.device_id
    tlsInsecure.value = state.tls_insecure
    uidMap.value = state.uid_map
    saved.value = { ...state }
    soterBetaEnabled.value = betaState.enabled
    status.value = 'ready'
  } catch (error) {
    if (currentGeneration !== generation || !props.modelValue) return
    status.value = 'error'
    errorMessage.value = error instanceof Error ? error.message : String(error)
  }
}

watch(() => props.modelValue, open => {
  if (open) void load()
  else generation++
}, { immediate: true })

onBeforeUnmount(() => { generation++ })

function requestClose(): boolean {
  if (busy.value) return false
  emit('update:modelValue', false)
  return true
}

defineExpose({ requestClose, busy })

function setAppEnabled(value: boolean): void {
  appEnabled.value = value
  if (value) enabled.value = false
}

function setGlobalEnabled(value: boolean): void {
  enabled.value = value
  if (value) appEnabled.value = false
}

async function apply(): Promise<void> {
  const state = current.value
  if (!canApply.value || !state) return
  busy.value = true
  errorMessage.value = ''
  try {
    saved.value = await props.cli.setSoterHal(state)
    emit('notify', tr('soter_hal_saved', 'Soter HAL configuration saved'))
    emit('update:modelValue', false)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
    emit('notify', errorMessage.value, true)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <MiuixDialog
    :model-value="modelValue"
    :title="tr('tools_soter_hal', 'Soter HAL configuration')"
    :close-on-click-modal="!busy"
    @update:model-value="value => { if (!value) requestClose() }"
  >
    <div class="soter-hal-dialog" :aria-busy="busy || status === 'loading'">
      <p>{{ tr('soter_hal_desc', 'Configure the Qualcomm Soter service.') }}</p>
      <p v-if="soterBetaEnabled" class="soter-hal-dialog__error">
        {{ tr('soter_hal_exclusive', 'Disable Tencent Soter Server (Testing) before enabling the Qualcomm Soter service.') }}
      </p>
      <div v-if="status === 'loading'" class="soter-hal-dialog__loading" role="status">
        <MiuixProgressIndicator type="circular" :size="28" />
        <span>{{ tr('home_status_loading', 'Checking') }}</span>
      </div>
      <template v-else-if="status === 'ready'">
        <p class="soter-hal-dialog__warning">
          {{ tr('soter_hal_warning', 'This feature may cause probabilistic bans of Douyin accounts and other unknown issues. Please consider carefully before enabling it.') }}
        </p>
        <MiuixSwitchPreference
          :model-value="appEnabled"
          :title="tr('soter_app_master', 'Take over SOTER for selected apps')"
          :disabled="busy"
          @update:model-value="setAppEnabled"
        />
        <p class="soter-hal-dialog__hint">
          {{ tr('soter_app_master_desc', 'Opt in each app using its settings in Add package names. Unselected apps keep the original SOTER service; ordinary OMK selection does not enable remote SOTER.') }}
        </p>
        <MiuixSwitchPreference
          v-model="remoteEnabled"
          :title="tr('soter_hal_remote_enabled', 'Enable remote Soter relay')"
          :disabled="busy"
        />
        <p class="soter-hal-dialog__hint">
          {{ tr('soter_hal_remote_desc', 'Allows SOTER requests to use the saved relay. In per-app mode, both this switch and the app-specific switch must be on.') }}
        </p>
        <p v-if="appEnabled" class="soter-hal-dialog__hint">
          {{ tr('soter_app_count', 'Apps with remote SOTER enabled') }}: {{ saved?.app_targets.length ?? 0 }}
        </p>
        <MiuixInput
          v-model="url"
          :label="tr('soter_hal_url', 'Soter server URL')"
          :disabled="busy"
        />
        <MiuixInput
          v-model="deviceId"
          :label="tr('soter_hal_device_id', 'B device ID')"
          :disabled="busy"
        />
        <MiuixInput
          v-model="token"
          :label="tr('soter_hal_token', 'Token')"
          :disabled="busy"
        />
        <MiuixInput
          v-model="uidMap"
          :label="tr('soter_hal_uid_map', 'UID mapping (optional)')"
          :disabled="busy"
        />
        <MiuixSwitchPreference
          v-model="tlsInsecure"
          :title="tr('soter_hal_tls_insecure', 'Accept self-signed TLS certificates')"
          :disabled="busy"
        />
        <details class="soter-hal-dialog__section">
          <summary>{{ tr('soter_hal_global_section', 'Qualcomm global HAL compatibility mode') }}</summary>
          <div class="soter-hal-dialog__section-body">
            <MiuixSwitchPreference
              :model-value="enabled"
              :title="tr('soter_hal_enabled', 'Enable global software TA')"
              :disabled="busy"
              @update:model-value="setGlobalEnabled"
            />
            <p class="soter-hal-dialog__warning">
              {{ tr('soter_hal_global_exclusive', 'Global HAL takeover affects all apps using this HAL and cannot be combined with per-app takeover. Enabling either mode disables the other when saved.') }}
            </p>
            <p class="soter-hal-dialog__hint">
              {{ tr('soter_hal_enabled_desc', 'The software TA takes over the stock Soter HAL. With the relay off, it uses its local ledger. Turning the software TA off restores the stock HAL.') }}
            </p>
          </div>
        </details>
      </template>
      <p v-if="errorMessage" class="soter-hal-dialog__error" role="alert">{{ errorMessage }}</p>
      <p v-if="preview" class="soter-hal-dialog__preview" role="status">
        {{ tr('soter_hal_preview', 'Preview only. Device settings cannot be saved here.') }}
      </p>
      <div class="soter-hal-dialog__actions">
        <MiuixButton :disabled="busy" @click="requestClose">
          {{ tr('functional_button_cancel', 'Cancel') }}
        </MiuixButton>
        <MiuixButton v-if="status === 'error'" type="primary" @click="load">
          {{ tr('functional_button_retry', 'Retry') }}
        </MiuixButton>
        <MiuixButton v-else type="primary" :disabled="!canApply" @click="apply">
          <MiuixProgressIndicator v-if="busy" type="circular" :size="18" />
          {{ tr('functional_button_save', 'Save') }}
        </MiuixButton>
      </div>
    </div>
  </MiuixDialog>
</template>

<style scoped>
.soter-hal-dialog { display: flex; flex-direction: column; gap: 14px; height: min(72vh, 620px); overflow-y: auto; }
.soter-hal-dialog p { margin: 0; color: var(--m-color-on-surface-variant-summary); font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; }
.soter-hal-dialog__warning { color: var(--m-color-on-surface) !important; }
.soter-hal-dialog__loading { display: flex; flex: 1; min-height: 64px; align-items: center; justify-content: center; gap: 12px; color: var(--m-color-on-surface-variant-summary); }
.soter-hal-dialog__error { color: var(--m-color-error) !important; }
.soter-hal-dialog__hint { font-size: 13px !important; }
.soter-hal-dialog__actions { display: flex; gap: 12px; }
.soter-hal-dialog__actions > * { flex: 1; min-width: 0; }
.soter-hal-dialog__section { color: var(--m-color-on-surface); }
.soter-hal-dialog__section summary { padding: 10px 0; font-size: 16px; cursor: pointer; }
.soter-hal-dialog__section-body { display: flex; flex-direction: column; gap: 12px; padding-block: 6px; }
.soter-hal-dialog :deep(.m-basic-component) { padding: 8px 0; }
.soter-hal-dialog :deep(.m-basic-component--clickable::after) { content: none; }
.soter-hal-dialog :deep(.m-basic-component--clickable:focus-visible .m-switch) { box-shadow: 0 0 0 2px var(--m-color-primary); }
.soter-hal-dialog :deep(.m-basic-component__center > .m-text--headline1) { font-size: 16px; line-height: 1.35; }
.soter-hal-dialog :deep(.m-basic-component__center > .m-text--body2) { font-size: 14px; line-height: 1.4; }
</style>

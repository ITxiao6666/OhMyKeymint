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
  return JSON.stringify(state) !== JSON.stringify(saved.value)
})

const softwareTakeoverEnabled = computed(() => enabled.value || appEnabled.value)

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

function setSoftwareTakeoverEnabled(value: boolean): void {
  // Keep both persisted bits in lockstep: this is one user-facing mode and
  // one watchdog transition, not two independently toggled operations.
  enabled.value = value
  appEnabled.value = value
}

async function apply(): Promise<void> {
  const state = current.value
  if (!canApply.value || !state) return
  const restoresStockInBackground = saved.value?.enabled === true
    && !state.enabled && !state.app_enabled
  busy.value = true
  errorMessage.value = ''
  try {
    await afterPaint()
    saved.value = await props.cli.setSoterHal(state)
    emit('notify', restoresStockInBackground
      ? tr('soter_hal_saved_background', 'Settings saved; stock Soter HAL restoration continues in the background.')
      : tr('soter_hal_saved', 'Soter HAL configuration saved'))
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
          :model-value="softwareTakeoverEnabled"
          :title="tr('soter_hal_enabled', 'Enable remote Soter service')"
          :disabled="busy"
          @update:model-value="setSoftwareTakeoverEnabled"
        />
        <p class="soter-hal-dialog__hint">
          {{ tr('soter_hal_enabled_desc', 'The software TA takes over the stock Soter HAL. Remote forwarding remains limited to apps individually enabled in Add package names; other apps use the software TA locally. Turning this off restores the stock Soter HAL.') }}
        </p>
        <MiuixSwitchPreference
          v-model="remoteEnabled"
          :title="tr('soter_hal_remote_enabled', 'Enable remote Soter relay')"
          :disabled="busy"
        />
        <p class="soter-hal-dialog__hint">
          {{ tr('soter_hal_remote_desc', 'Allows SOTER requests to use the saved relay. In per-app mode, both this switch and the app-specific switch must be on.') }}
        </p>
        <p v-if="saved?.app_targets.length" class="soter-hal-dialog__hint">
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
.soter-hal-dialog :deep(.m-basic-component) { padding: 8px 0; }
.soter-hal-dialog :deep(.m-basic-component--clickable::after) { content: none; }
.soter-hal-dialog :deep(.m-basic-component--clickable:focus-visible .m-switch) { box-shadow: 0 0 0 2px var(--m-color-primary); }
.soter-hal-dialog :deep(.m-basic-component__center > .m-text--headline1) { font-size: 16px; line-height: 1.35; }
.soter-hal-dialog :deep(.m-basic-component__center > .m-text--body2) { font-size: 14px; line-height: 1.4; }
</style>

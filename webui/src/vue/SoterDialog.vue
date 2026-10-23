<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import {
  MiuixButton,
  MiuixDialog,
  MiuixProgressIndicator,
  MiuixSwitchPreference,
} from 'miuix-vue'
import { Cli } from '../cli'
import { afterPaint } from '../app_list/app_list'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

const props = defineProps<{ modelValue: boolean, cli: Cli }>()
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  notify: [message: string, error?: boolean]
}>()

const preview = isDev()
const enabled = ref(false)
const savedEnabled = ref(false)
const soterHalEnabled = ref(false)
const status = ref<'loading' | 'ready' | 'error'>('loading')
const errorMessage = ref('')
const busy = ref(false)
let generation = 0

const canApply = computed(() => !preview
  && !busy.value
  && status.value === 'ready'
  && enabled.value !== savedEnabled.value
  && (!enabled.value || !soterHalEnabled.value))

function tr(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

async function load(): Promise<void> {
  if (!props.modelValue || busy.value) return
  const currentGeneration = ++generation
  status.value = 'loading'
  errorMessage.value = ''
  enabled.value = false
  soterHalEnabled.value = false
  try {
    await afterPaint()
    if (currentGeneration !== generation || !props.modelValue) return
    const [state, halState] = preview
      ? [{ enabled: false }, { enabled: false, app_enabled: false }]
      : await Promise.all([props.cli.getSoterBeta(), props.cli.getSoterHal()])
    if (currentGeneration !== generation || !props.modelValue) return
    enabled.value = state.enabled
    savedEnabled.value = state.enabled
    soterHalEnabled.value = halState.enabled || halState.app_enabled
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

async function apply(): Promise<void> {
  if (!canApply.value) return
  busy.value = true
  errorMessage.value = ''
  try {
    await afterPaint()
    await props.cli.setSoterBeta(enabled.value)
    savedEnabled.value = enabled.value
    emit('notify', tr('soter_beta_applied', 'Settings saved; SoterServer will reconnect using the selected mode. No device reboot is needed.'))
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
    :title="tr('tools_soter_beta', 'Fix Tencent Soter Server (Testing)')"
    :close-on-click-modal="!busy"
    @update:model-value="value => { if (!value) requestClose() }"
  >
    <div class="soter-dialog" :aria-busy="busy || status === 'loading'">
      <p class="soter-dialog__warning">
        {{ tr('soter_beta_warning', 'This feature is in testing and only addresses some detector checks. It does not repair TEE fingerprint functionality.') }}
      </p>
      <p>{{ tr('soter_beta_reboot', 'Install the Zygisk Next module before enabling this feature.') }}</p>
      <p v-if="soterHalEnabled" class="soter-dialog__warning">
        {{ tr('soter_beta_mode_exclusive', 'Disable global HAL takeover and per-app remote SOTER before enabling Tencent Soter Server (Testing).') }}
      </p>

      <div v-if="status === 'loading'" class="soter-dialog__loading" role="status">
        <MiuixProgressIndicator type="circular" :size="28" />
        <span>{{ tr('home_status_loading', 'Checking') }}</span>
      </div>
      <MiuixSwitchPreference
        v-else-if="status === 'ready'"
        v-model="enabled"
        :title="tr('soter_beta_enabled', 'Enable Soter compatibility')"
        :summary="tr('soter_beta_enabled_desc', 'Disabled by default. Changes are saved only after you tap Apply.')"
        :disabled="busy"
      />
      <p v-if="errorMessage" class="soter-dialog__error" role="alert">{{ errorMessage }}</p>
      <p v-if="preview" class="soter-dialog__preview" role="status">
        {{ tr('soter_beta_preview', 'Preview only. Device settings cannot be saved here.') }}
      </p>

      <div class="soter-dialog__actions">
        <MiuixButton :disabled="busy" @click="requestClose">
          {{ tr('functional_button_cancel', 'Cancel') }}
        </MiuixButton>
        <MiuixButton v-if="status === 'error'" type="primary" @click="load">
          {{ tr('functional_button_retry', 'Retry') }}
        </MiuixButton>
        <MiuixButton v-else type="primary" :disabled="!canApply" @click="apply">
          <MiuixProgressIndicator v-if="busy" type="circular" :size="18" />
          {{ tr('functional_button_apply', 'Apply') }}
        </MiuixButton>
      </div>
    </div>
  </MiuixDialog>
</template>

<style scoped>
.soter-dialog { display: flex; flex-direction: column; gap: 14px; }
.soter-dialog p { margin: 0; color: var(--m-color-on-surface-variant-summary); font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; }
.soter-dialog .soter-dialog__warning { color: var(--m-color-on-surface); }
.soter-dialog .soter-dialog__error { color: var(--m-color-error); }
.soter-dialog__loading { display: flex; min-height: 64px; align-items: center; justify-content: center; gap: 12px; color: var(--m-color-on-surface-variant-summary); }
.soter-dialog__actions { display: flex; gap: 12px; }
.soter-dialog__actions > * { flex: 1; min-width: 0; }
.soter-dialog :deep(.m-basic-component) { padding: 8px 0; }
.soter-dialog :deep(.m-basic-component__center > .m-text--headline1) { font-size: 16px; line-height: 1.35; }
.soter-dialog :deep(.m-basic-component__center > .m-text--body2) { font-size: 14px; line-height: 1.4; }
</style>

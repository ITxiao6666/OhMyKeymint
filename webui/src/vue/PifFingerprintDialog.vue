<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  MiuixBasicComponent,
  MiuixBottomSheet,
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixProgressIndicator,
  MiuixRadioButtonPreference,
  MiuixSwitchPreference,
} from 'miuix-vue'
import { Info, Refresh, Tune } from 'miuix-vue/icons'
import { Cli, type PifDevice, type PifFingerprintState } from '../cli'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

type LoadStatus = 'loading' | 'ready' | 'error'
const RANDOM_SELECTION = '__random__'

const props = defineProps<{
  modelValue: boolean
  cli: Cli
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  changed: []
  notify: [message: string, error?: boolean]
}>()

const currentState = ref<PifFingerprintState | null>(null)
const devices = ref<PifDevice[]>([])
const stateStatus = ref<LoadStatus>('loading')
const catalogStatus = ref<LoadStatus>('loading')
const stateError = ref('')
const catalogError = ref('')
const desiredEnabled = ref(false)
const selectedProduct = ref<string | null>(RANDOM_SELECTION)
const loadGeneration = ref(0)
const busy = ref(false)

function tr(key: string, fallback: string, ...args: unknown[]): string {
  const value = i18n.t(key, ...args)
  if (value !== key) return value
  let index = 0
  return fallback.replace(/%s/g, () => String(args[index++] ?? ''))
}

const canApply = computed(() => stateStatus.value === 'ready'
  && (!desiredEnabled.value
    || (catalogStatus.value === 'ready'
      && selectedProduct.value !== null
      && devices.value.length > 0)))

watch(() => props.modelValue, open => {
  if (open) load()
  else loadGeneration.value++
})

function isActive(generation: number): boolean {
  return generation === loadGeneration.value && props.modelValue
}

function reconcileSelection(): void {
  if (stateStatus.value !== 'ready' || catalogStatus.value !== 'ready') return
  if (selectedProduct.value === RANDOM_SELECTION) return
  if (selectedProduct.value !== null
      && devices.value.some(device => device.product === selectedProduct.value)) return
  selectedProduct.value = currentState.value?.enabled ? null : RANDOM_SELECTION
}

function load(): void {
  currentState.value = null
  devices.value = []
  stateStatus.value = 'loading'
  catalogStatus.value = 'loading'
  stateError.value = ''
  catalogError.value = ''
  desiredEnabled.value = false
  selectedProduct.value = RANDOM_SELECTION
  const generation = ++loadGeneration.value
  void loadState(generation)
  void loadCatalog(generation)
}

async function loadState(generation: number): Promise<void> {
  try {
    const state = isDev()
      ? ({
          enabled: true,
          model: 'Pixel 9 Pro',
          product: 'komodo',
          fingerprint: 'google/komodo/komodo:16/BP2A/example:user/release-keys',
          security_patch: '2026-08-05',
        } satisfies PifFingerprintState)
      : await props.cli.getPifFingerprintState()
    if (!isActive(generation)) return
    currentState.value = state
    desiredEnabled.value = state.enabled
    selectedProduct.value = state.enabled ? state.product : RANDOM_SELECTION
    stateStatus.value = 'ready'
    reconcileSelection()
  } catch (error) {
    if (!isActive(generation)) return
    stateStatus.value = 'error'
    stateError.value = error instanceof Error ? error.message : String(error)
  }
}

async function loadCatalog(generation: number): Promise<void> {
  try {
    const result = isDev()
      ? [
          { model: 'Pixel 9 Pro', product: 'komodo' },
          { model: 'Pixel 9', product: 'tokay' },
          { model: 'Pixel 8 Pro', product: 'husky' },
          { model: 'Pixel 8', product: 'shiba' },
        ]
      : await props.cli.listPifDevices()
    if (!isActive(generation)) return
    devices.value = result
    catalogStatus.value = 'ready'
    reconcileSelection()
  } catch (error) {
    if (!isActive(generation)) return
    catalogStatus.value = 'error'
    catalogError.value = error instanceof Error ? error.message : String(error)
  }
}

function retryState(): void {
  if (busy.value || !props.modelValue) return
  stateStatus.value = 'loading'
  stateError.value = ''
  void loadState(loadGeneration.value)
}

function retryCatalog(): void {
  if (busy.value || !props.modelValue) return
  catalogStatus.value = 'loading'
  catalogError.value = ''
  void loadCatalog(loadGeneration.value)
}

function requestClose(): boolean {
  if (busy.value) return false
  emit('update:modelValue', false)
  return true
}

// App.vue owns the shared History stack. Expose the guarded close operation so
// a back/Escape request can ask this sheet to close without bypassing the busy
// protection used by the native bottom-sheet scrim.
defineExpose({ requestClose, busy })

async function apply(): Promise<void> {
  if (busy.value || !canApply.value) return

  let device: PifDevice | undefined
  if (desiredEnabled.value) {
    device = selectedProduct.value === RANDOM_SELECTION
      ? devices.value[Math.floor(Math.random() * devices.value.length)]
      : devices.value.find(item => item.product === selectedProduct.value)
    if (!device) return
  }

  busy.value = true
  try {
    if (device) {
      const state = isDev()
        ? ({
            enabled: true,
            model: device.model,
            product: device.product,
            fingerprint: `google/${device.product}/${device.product}:16/preview:user/release-keys`,
            security_patch: '2026-08-05',
          } satisfies PifFingerprintState)
        : await props.cli.applyPifFingerprint(device.product)
      currentState.value = state
      emit('notify', tr(
        'prompt_pif_applied',
        'PIF fingerprint applied: %s, security patch %s.',
        state.model,
        state.security_patch,
      ))
    } else {
      currentState.value = isDev()
        ? { enabled: false }
        : await props.cli.disablePifFingerprint()
      emit('notify', tr('prompt_pif_disabled', 'PIF fingerprint spoofing disabled.'))
    }
    emit('changed')
    emit('update:modelValue', false)
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    console.error('Unable to update PIF fingerprint spoofing:', error)
    emit('notify', tr('prompt_pif_apply_error', 'Unable to apply PIF fingerprint: %s', detail), true)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <MiuixBottomSheet
    :model-value="modelValue"
    :title="tr('pif_fingerprint_title', 'Spoof PIF fingerprint')"
    :allow-dismiss="!busy"
    :close-on-click-modal="!busy"
    @update:model-value="value => value ? undefined : requestClose()"
    @close="requestClose"
  >
    <div class="pif-sheet" :aria-busy="busy">
      <MiuixCard class="pif-card" press-feedback="none">
        <MiuixSwitchPreference
          v-model="desiredEnabled"
          :title="tr('pif_enable_spoofing', 'Enable PIF fingerprint spoofing')"
          :summary="tr('pif_zygisk_next_required', 'Install and enable Zygisk Next separately. OMK does not bundle it.')"
          :disabled="busy || stateStatus !== 'ready'"
        >
          <template #start><MiuixIcon :icon="Tune" :size="23" /></template>
        </MiuixSwitchPreference>
      </MiuixCard>

      <MiuixCard
        v-if="stateStatus === 'ready' && currentState !== null"
        class="pif-card current-config"
        press-feedback="none"
      >
        <MiuixBasicComponent :title="tr('pif_current_config', 'Current configuration')">
          <template #bottom>
            <div class="current-config-values">
              <strong>{{ currentState.enabled ? currentState.model : tr('pif_disabled', 'Disabled') }}</strong>
              <span v-if="currentState.enabled">
                {{ tr('pif_security_patch', 'Security patch: %s', currentState.security_patch) }}
              </span>
            </div>
          </template>
        </MiuixBasicComponent>
      </MiuixCard>

      <div v-if="stateStatus === 'loading'" class="pif-status" role="status">
        <MiuixProgressIndicator type="circular" :size="26" :stroke-width="2.5" />
        <span>{{ tr('pif_loading_config', 'Loading PIF configuration...') }}</span>
      </div>
      <div v-else-if="stateStatus === 'error'" class="pif-status pif-status--error" role="alert">
        <MiuixIcon :icon="Info" :size="24" />
        <strong>{{ tr('pif_config_load_error', 'Failed to load the PIF configuration') }}</strong>
        <span v-if="stateError">{{ stateError }}</span>
        <MiuixButton :disabled="busy" @click="retryState">
          <MiuixIcon :icon="Refresh" :size="18" />
          {{ tr('functional_button_retry', 'Retry') }}
        </MiuixButton>
      </div>
      <div v-else-if="!desiredEnabled" class="pif-status" role="status">
        <span>{{ tr('pif_disabled', 'Disabled') }}</span>
      </div>
      <div v-else-if="catalogStatus === 'loading'" class="pif-status" role="status">
        <MiuixProgressIndicator type="circular" :size="26" :stroke-width="2.5" />
        <span>{{ tr('pif_loading_devices', 'Loading Pixel devices...') }}</span>
      </div>
      <div v-else-if="catalogStatus === 'error'" class="pif-status pif-status--error" role="alert">
        <MiuixIcon :icon="Info" :size="24" />
        <strong>{{ tr('pif_devices_load_error', 'Failed to load Pixel devices') }}</strong>
        <span v-if="catalogError">{{ catalogError }}</span>
        <MiuixButton :disabled="busy" @click="retryCatalog">
          <MiuixIcon :icon="Refresh" :size="18" />
          {{ tr('functional_button_retry', 'Retry') }}
        </MiuixButton>
      </div>
      <template v-else>
        <h3>{{ tr('pif_choose_device', 'Choose a Pixel device') }}</h3>
        <MiuixCard class="pif-card device-list" press-feedback="none">
          <MiuixRadioButtonPreference
            :model-value="selectedProduct === RANDOM_SELECTION"
            :title="tr('pif_random_device', 'Random')"
            :disabled="busy"
            @select="selectedProduct = RANDOM_SELECTION"
          />
          <MiuixRadioButtonPreference
            v-for="device in devices"
            :key="device.product"
            :model-value="selectedProduct === device.product"
            :title="device.model"
            :summary="device.product"
            :disabled="busy"
            @select="selectedProduct = device.product"
          />
        </MiuixCard>
      </template>

      <div class="sheet-actions">
        <MiuixButton :disabled="busy" @click="requestClose">
          {{ tr('functional_button_cancel', 'Cancel') }}
        </MiuixButton>
        <MiuixButton type="primary" :disabled="busy || !canApply" @click="apply">
          <MiuixProgressIndicator
            v-if="busy"
            type="circular"
            :size="19"
            :stroke-width="2.5"
          />
          {{ tr(busy ? 'pif_applying' : 'functional_button_apply', busy ? 'Applying...' : 'Apply') }}
        </MiuixButton>
      </div>
    </div>
  </MiuixBottomSheet>
</template>

<style scoped>
.pif-sheet {
  display: grid;
  gap: 12px;
  padding: 2px 0 max(18px, env(safe-area-inset-bottom));
}

.pif-card {
  flex: none;
}

.current-config-values {
  display: grid;
  gap: 3px;
  min-width: 0;
}

.current-config-values strong,
.current-config-values span {
  overflow-wrap: anywhere;
}

.current-config-values span {
  color: var(--m-color-on-surface-variant-summary);
  font-size: var(--m-text-body2-size);
}

.pif-sheet h3 {
  margin: 4px 16px 0;
  font-size: var(--m-text-subtitle-size);
}

.device-list {
  max-height: min(45vh, 390px);
  overflow: hidden auto;
  scrollbar-width: none;
}

.device-list::-webkit-scrollbar {
  display: none;
}

.pif-status {
  min-height: 112px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 16px;
  text-align: center;
  color: var(--m-color-on-surface-variant-summary);
}

.pif-status--error {
  color: var(--m-color-error);
}

.pif-status .m-button {
  display: inline-flex;
  gap: 7px;
  margin-top: 4px;
}

.sheet-actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  position: sticky;
  bottom: 0;
  padding-top: 8px;
  background: var(--m-color-background);
}

.sheet-actions .m-button {
  gap: 7px;
}
</style>

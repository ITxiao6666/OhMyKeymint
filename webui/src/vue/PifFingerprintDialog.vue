<script setup lang="ts">
import { computed, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import {
  MiuixBasicComponent,
  MiuixBottomSheet,
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixProgressIndicator,
  MiuixRadioButtonPreference,
  MiuixSwitch,
  MiuixSwitchPreference,
} from 'miuix-vue'
import { Info, Refresh, Tune } from 'miuix-vue/icons'
import { afterPaint } from '../app_list/app_list'
import { Cli, type PifDevice, type PifFingerprintState } from '../cli'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

type LoadStatus = 'loading' | 'ready' | 'error'
const RANDOM_SELECTION = '__random__'
const preview = isDev()
const previewDevices = [
  { model: 'Pixel 6a', product: 'bluejay_beta', sdk: 32 },
  { model: 'Pixel 9 Pro', product: 'caiman_beta', sdk: 34 },
  { model: 'Pixel 11 Pro XL', product: 'kodiak_beta', sdk: 37 },
]
let previewState: PifFingerprintState = {
  enabled: true,
  model: 'Pixel 6a',
  product: 'bluejay_beta',
  fingerprint: 'google/bluejay_beta/bluejay:CANARY/ZP11.260918.007/16484274:user/release-keys',
  security_patch: '2026-10-05',
  device_initial_sdk_int: 32,
  spoof_build: true,
  spoof_props: true,
  spoof_vending_build: false,
}

const props = defineProps<{
  modelValue: boolean
  cli: Cli
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  changed: []
  notify: [message: string, error?: boolean]
}>()

const currentState = shallowRef<PifFingerprintState | null>(null)
const devices = shallowRef<PifDevice[]>([])
const renderedDeviceCount = ref(0)
const renderedDevices = computed(() => devices.value.slice(0, renderedDeviceCount.value))
const stateStatus = ref<LoadStatus>('loading')
const catalogStatus = ref<LoadStatus>('loading')
const stateError = ref('')
const catalogError = ref('')
const desiredEnabled = ref(false)
const spoofBuild = ref(true)
const spoofProps = ref(true)
const spoofVendingBuild = ref(false)
const selectedProduct = ref<string | null>(RANDOM_SELECTION)
let loadGeneration = 0
let catalogRequested = false
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
  else loadGeneration++
}, { immediate: true })

// Radio preferences carry their own animations. Fill the visible viewport first
// instead of mounting the full downloaded catalog in one opening frame.
watch([() => props.modelValue, desiredEnabled, catalogStatus, devices], async ([open, enabled, status, items], _, onCleanup) => {
  let cancelled = false
  onCleanup(() => { cancelled = true })
  // A disabled profile can be inspected or disabled without downloading the
  // catalog. Fetch it only when device selection is actually displayed.
  if (open && enabled && status === 'loading' && !catalogRequested) {
    catalogRequested = true
    void loadCatalog(loadGeneration)
  }
  renderedDeviceCount.value = open && enabled && status === 'ready' ? Math.min(16, items.length) : 0
  if (!renderedDeviceCount.value) return
  while (renderedDeviceCount.value < items.length) {
    await afterPaint()
    if (cancelled) return
    renderedDeviceCount.value = Math.min(renderedDeviceCount.value + 16, items.length)
  }
}, { immediate: true })

onBeforeUnmount(() => { loadGeneration++ })

function isActive(generation: number): boolean {
  return generation === loadGeneration && props.modelValue
}

function reconcileSelection(): void {
  if (stateStatus.value !== 'ready' || catalogStatus.value !== 'ready') return
  if (selectedProduct.value === RANDOM_SELECTION) return
  if (selectedProduct.value !== null
      && devices.value.some(device => device.product === selectedProduct.value)) return
  selectedProduct.value = currentState.value?.enabled ? null : RANDOM_SELECTION
}

function load(): void {
  if (!props.modelValue || busy.value) return
  catalogRequested = false
  currentState.value = null
  devices.value = []
  stateStatus.value = 'loading'
  catalogStatus.value = 'loading'
  stateError.value = ''
  catalogError.value = ''
  desiredEnabled.value = false
  spoofBuild.value = true
  spoofProps.value = true
  spoofVendingBuild.value = false
  selectedProduct.value = RANDOM_SELECTION
  const generation = ++loadGeneration
  void loadState(generation)
}

async function loadState(generation: number): Promise<void> {
  try {
    await afterPaint()
    if (!isActive(generation)) return
    const state = preview
      ? previewState
      : await props.cli.getPifFingerprintState()
    if (!isActive(generation)) return
    currentState.value = state
    desiredEnabled.value = state.enabled
    spoofBuild.value = state.enabled ? state.spoof_build : true
    spoofProps.value = state.enabled ? state.spoof_props : true
    spoofVendingBuild.value = state.enabled ? state.spoof_vending_build : false
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
    await afterPaint()
    if (!isActive(generation)) return
    const result = preview
      ? previewDevices
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
  if (busy.value || !props.modelValue || stateStatus.value === 'loading') return
  stateStatus.value = 'loading'
  stateError.value = ''
  void loadState(loadGeneration)
}

function retryCatalog(): void {
  if (busy.value || !props.modelValue || catalogStatus.value === 'loading') return
  catalogStatus.value = 'loading'
  catalogError.value = ''
  void loadCatalog(loadGeneration)
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
    if (preview) {
      const sample = previewDevices.find(item => item.product === device?.product)
      previewState = sample ? {
        enabled: true,
        model: sample.model,
        product: sample.product,
        fingerprint: `google/${sample.product}/${sample.product.replace(/_beta$/, '')}:CANARY/ZP11.260918.007/16484274:user/release-keys`,
        security_patch: '2026-10-05',
        device_initial_sdk_int: sample.sdk,
        spoof_build: spoofBuild.value,
        spoof_props: spoofProps.value,
        spoof_vending_build: spoofVendingBuild.value,
      } : { enabled: false }
      currentState.value = previewState
      emit('notify', tr('pif_preview_applied', 'Preview updated only; no phone settings were changed.'))
      return
    }
    if (device) {
      const state = await props.cli.applyPifFingerprint(
        device.product, spoofBuild.value, spoofProps.value, spoofVendingBuild.value,
      )
      currentState.value = state
      emit('notify', tr(
        'prompt_pif_applied',
        'PIF fingerprint applied: %s, security patch %s.',
        state.model,
        state.security_patch,
      ))
    } else {
      currentState.value = await props.cli.disablePifFingerprint()
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
      <p v-if="preview" class="pif-preview" role="status">
        {{ tr('pif_preview', 'Browser preview with example data. No device configuration is changed.') }}
      </p>
      <MiuixCard class="pif-card" press-feedback="none">
        <!-- Toggle on click, not the switch's pointerup: collapsing this sheet
             before click can retarget it to the backdrop and discard the edit. -->
        <MiuixBasicComponent
          clickable
          role="switch"
          :aria-checked="desiredEnabled"
          :aria-label="tr('pif_enable_spoofing', 'Enable PIF fingerprint spoofing')"
          :aria-disabled="busy || stateStatus !== 'ready'"
          :title="tr('pif_enable_spoofing', 'Enable PIF fingerprint spoofing')"
          :summary="tr('pif_zygisk_next_required', 'Install and enable Zygisk Next separately. OMK does not bundle it.')"
          :disabled="busy || stateStatus !== 'ready'"
          @click="desiredEnabled = !desiredEnabled"
        >
          <template #start><MiuixIcon :icon="Tune" :size="23" /></template>
          <template #end>
            <MiuixSwitch
              class="pif-enable-control"
              :model-value="desiredEnabled"
              :disabled="busy || stateStatus !== 'ready'"
              tabindex="-1"
              aria-hidden="true"
            />
          </template>
        </MiuixBasicComponent>
      </MiuixCard>

      <MiuixCard v-if="desiredEnabled && stateStatus === 'ready'" class="pif-card" press-feedback="none">
        <MiuixSwitchPreference
          v-model="spoofBuild"
          :title="tr('pif_spoof_build', 'Spoof Build')"
          :summary="tr('pif_spoof_build_desc', 'Apply Pixel Build fields and the launch SDK to Google Play services only; the running Android SDK stays unchanged.')"
          :disabled="busy"
        />
        <MiuixSwitchPreference
          v-model="spoofVendingBuild"
          :title="tr('pif_spoof_vending', 'Spoof Build (Play Store)')"
          :summary="tr('pif_spoof_vending_desc', 'Apply the selected Pixel Build fields to Play Store, including model, fingerprint and patch date. Independent of GMS; SDK and native properties stay unchanged.')"
          :disabled="busy"
        />
        <MiuixSwitchPreference
          v-model="spoofProps"
          :title="tr('pif_spoof_props', 'Spoof Props')"
          :summary="tr('pif_spoof_props_desc', 'Override selected property reads in Google Play services only; global and Play Store properties stay unchanged.')"
          :disabled="busy"
        />
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
              <span v-if="currentState.enabled">
                {{ tr('pif_initial_sdk', 'Initial SDK: %s', currentState.device_initial_sdk_int) }}
              </span>
              <code v-if="currentState.enabled" class="current-fingerprint">{{ currentState.fingerprint }}</code>
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
        <div class="catalog-heading">
          <h3>{{ tr('pif_choose_device', 'Choose a Pixel device') }}</h3>
          <MiuixButton :disabled="busy" @click="retryCatalog">
            <MiuixIcon :icon="Refresh" :size="18" />
            {{ tr('pif_refresh_devices', 'Refresh list') }}
          </MiuixButton>
        </div>
        <MiuixCard class="pif-card device-list" press-feedback="none">
          <MiuixRadioButtonPreference
            :model-value="selectedProduct === RANDOM_SELECTION"
            :title="tr('pif_random_device', 'Random')"
            :disabled="busy"
            @select="selectedProduct = RANDOM_SELECTION"
          />
          <MiuixRadioButtonPreference
            v-for="device in renderedDevices"
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
          {{ busy ? tr('pif_applying', 'Applying...') : preview ? tr('pif_preview_apply', 'Preview changes') : tr('functional_button_apply', 'Apply') }}
        </MiuixButton>
      </div>
    </div>
  </MiuixBottomSheet>
</template>

<style scoped>
.pif-sheet {
  display: flex;
  flex-direction: column;
  min-height: min(50vh, 420px);
  gap: 12px;
  padding: 2px 0 max(18px, env(safe-area-inset-bottom));
}

.pif-card {
  flex: none;
}

.pif-enable-control {
  pointer-events: none;
}

.pif-preview {
  margin: 0;
  padding: 0 16px;
  color: var(--m-color-on-surface-variant-summary);
  font-size: var(--m-text-body2-size);
  line-height: 1.5;
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

.current-fingerprint {
  white-space: normal;
  overflow-wrap: anywhere;
  font-size: 12px;
  line-height: 1.5;
  color: var(--m-color-on-surface-variant-summary);
}

.catalog-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.catalog-heading .m-button {
  display: inline-flex;
  gap: 6px;
  flex: none;
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
  /* The card's inner radius scrolls away; clip its outer viewport as well. */
  border-radius: var(--m-radius-md);
  overflow: hidden auto;
  scrollbar-width: none;
}

.device-list::-webkit-scrollbar {
  display: none;
}

.pif-status {
  flex: 1;
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
  flex: none;
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

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { MiuixButton, MiuixCard, MiuixIconButton, MiuixIcon, MiuixProgressIndicator,
  MiuixRadioButtonPreference, MiuixSwitchPreference } from 'miuix-vue'
import { Close } from 'miuix-vue/icons'
import MiuixBottomSheet from './StableBottomSheet.vue'
import { type Cli, type SoterIdentityState } from '../cli'
import { afterPaint } from '../app_list/app_list'
import { i18n } from '../i18n'
import { isDev } from '../utils/dev'

const props = defineProps<{ modelValue: boolean, cli: Cli, target?: string, batchTargets?: string[] }>()
const emit = defineEmits<{ 'update:modelValue': [open: boolean] }>()
const state = ref<SoterIdentityState | null>(null)
const busy = ref(false)
const error = ref('')
const selected = ref('')
const cpu = ref('')
const pendingDelete = ref<SoterIdentityState['identities'][number] | null>(null)
const batchConfirm = ref(false)
const batchMode = computed(() => props.batchTargets !== undefined)
const batchPending = computed(() => (props.batchTargets ?? []).filter(target => !state.value?.apps[target]))
const batchIdentity = computed(() => state.value?.identities.find(identity => identity.id === selected.value))
let generation = 0
const title = computed(() => batchMode.value ? i18n.t('soter_bulk_title') : (props.target || i18n.t('soter_local_title')))

async function load(): Promise<void> {
  const current = ++generation
  state.value = null
  pendingDelete.value = null
  batchConfirm.value = false
  error.value = ''
  try {
    await afterPaint()
    const value: SoterIdentityState = isDev()
      ? { version: 1, enabled: false, identities: [], apps: {} }
      : await props.cli.getSoterLocal()
    if (current !== generation || !props.modelValue) return
    state.value = value
    const app = props.target ? value.apps[props.target] : null
    selected.value = app?.identity ?? (batchMode.value ? value.identities[0]?.id ?? '' : '')
    cpu.value = app?.cpu_id ?? ''
  } catch (reason) {
    if (current === generation) error.value = String(reason)
  }
}

watch(() => [props.modelValue, props.target] as const, ([open]) => {
  if (open) void load()
  else generation++
}, { immediate: true })

async function change(value: Parameters<Cli['changeSoterLocal']>[0]): Promise<void> {
  if (busy.value || !state.value || isDev()) return
  busy.value = true
  error.value = ''
  try {
    await afterPaint()
    state.value = await props.cli.changeSoterLocal(value)
    pendingDelete.value = null
    if (value.action === 'app' || value.action === 'apps') requestClose(true)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : String(reason)
  } finally { busy.value = false }
}

function saveApp(): void {
  if (!props.target) return
  if (selected.value && cpu.value.trim() && !/^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{36})$/.test(cpu.value.trim())) {
    error.value = i18n.t('soter_cpu_invalid')
    return
  }
  void change({ action: 'app', target: props.target, identity: selected.value || null,
    cpu_id: selected.value ? cpu.value.trim() : '' })
}

function requestClose(completed = false): boolean {
  if (busy.value && !completed) return false
  emit('update:modelValue', false)
  return true
}
defineExpose({ busy, requestClose })
</script>

<template>
  <MiuixBottomSheet :model-value="modelValue" :title="title" :close-on-click-modal="!busy"
    :allow-dismiss="!busy"
    @update:model-value="value => { if (!value) requestClose() }">
    <template #start-action>
      <MiuixIconButton :disabled="busy" :aria-label="i18n.t('functional_button_cancel')" @click="requestClose()">
        <MiuixIcon :icon="Close" />
      </MiuixIconButton>
    </template>
    <div class="soter-local-sheet" :aria-busy="busy">
      <p class="soter-note">{{ i18n.t('soter_local_desc') }}</p>
      <MiuixProgressIndicator v-if="!state && !error" type="circular" :size="30" />
      <template v-if="state">
        <template v-if="batchMode">
          <p class="soter-note">{{ i18n.t('soter_bulk_desc') }}</p>
          <template v-if="batchConfirm && batchIdentity">
            <strong>{{ batchIdentity.name }}</strong>
            <p class="soter-note">{{ i18n.t('soter_bulk_confirm_desc', batchPending.length) }}</p>
            <MiuixButton :disabled="busy" @click="batchConfirm = false">
              {{ i18n.t('functional_button_cancel') }}
            </MiuixButton>
            <MiuixButton type="primary" :disabled="busy || isDev() || !batchPending.length"
              @click="change({ action: 'apps', targets: batchPending, identity: selected })">
              {{ i18n.t('soter_bulk_apply') }}
            </MiuixButton>
          </template>
          <template v-else>
            <MiuixRadioButtonPreference v-for="identity in state.identities" :key="identity.id"
              :model-value="selected === identity.id" :disabled="busy"
              :title="identity.name" @select="selected = identity.id" />
            <p v-if="!state.identities.length" class="soter-note">{{ i18n.t('soter_local_empty') }}</p>
            <p v-if="!batchTargets?.length" class="soter-note">{{ i18n.t('soter_bulk_no_apps') }}</p>
            <p v-else-if="!batchPending.length" class="soter-note">{{ i18n.t('soter_bulk_all_assigned') }}</p>
            <p v-else class="soter-note">{{ i18n.t('soter_bulk_confirm_desc', batchPending.length) }}</p>
            <MiuixButton type="primary" :disabled="busy || isDev() || !batchIdentity || !batchPending.length"
              @click="batchConfirm = true">
              {{ i18n.t('functional_button_save') }}
            </MiuixButton>
          </template>
          <p v-if="!state.enabled" class="soter-note">{{ i18n.t('soter_local_inactive') }}</p>
        </template>
        <template v-else-if="pendingDelete">
          <strong>{{ pendingDelete.name }}</strong>
          <p class="soter-note">{{ i18n.t('soter_local_delete_warning') }}</p>
          <MiuixButton :disabled="busy" @click="pendingDelete = null">
            {{ i18n.t('functional_button_cancel') }}
          </MiuixButton>
          <MiuixButton type="primary" :disabled="busy || isDev()"
            @click="change({ action: 'remove', id: pendingDelete.id })">
            {{ i18n.t('soter_local_delete_confirm') }}
          </MiuixButton>
        </template>
        <template v-else-if="!target">
          <MiuixCard press-feedback="none">
            <MiuixSwitchPreference :model-value="state.enabled" :disabled="busy || isDev()"
              :title="i18n.t('soter_local_enabled')" :summary="i18n.t('soter_local_enabled_desc')"
              @update:model-value="enabled => change({ action: 'enabled', enabled })" />
          </MiuixCard>
          <MiuixCard v-for="identity in state.identities" :key="identity.id" press-feedback="none">
            <div class="soter-identity">
              <div class="soter-identity-heading"><strong>{{ identity.name }}</strong>
                <MiuixButton :disabled="busy || isDev()" @click="pendingDelete = identity">
                  {{ i18n.t('soter_local_delete') }}
                </MiuixButton>
              </div>
            </div>
          </MiuixCard>
          <MiuixButton :disabled="busy || isDev() || state.identities.length >= 32"
            @click="change({ action: 'add', name: i18n.t('soter_local_random') + ' ' + (state.identities.length + 1) })">
            {{ i18n.t('soter_local_add') }}
          </MiuixButton>
        </template>
        <template v-else>
          <MiuixRadioButtonPreference :model-value="selected === ''" :disabled="busy"
            :title="i18n.t('soter_local_stock')" @select="selected = ''" />
          <MiuixRadioButtonPreference v-for="identity in state.identities" :key="identity.id"
            :model-value="selected === identity.id" :disabled="busy"
            :title="identity.name" @select="selected = identity.id" />
          <label v-if="selected" class="soter-cpu-field">
            <span>{{ i18n.t('soter_cpu_override') }}</span>
            <input v-model="cpu" :disabled="busy" maxlength="36" spellcheck="false"
              autocapitalize="none" autocomplete="off" :placeholder="i18n.t('soter_cpu_placeholder')">
          </label>
          <p v-if="!state.identities.length" class="soter-note">{{ i18n.t('soter_local_empty') }}</p>
          <p v-if="!state.enabled" class="soter-note">{{ i18n.t('soter_local_inactive') }}</p>
          <MiuixButton type="primary" :disabled="busy || isDev()" @click="saveApp">
            {{ i18n.t('functional_button_save') }}
          </MiuixButton>
        </template>
        <MiuixProgressIndicator v-if="busy" type="circular" :size="24" />
      </template>
      <p v-if="error" role="alert" class="soter-error">{{ error }}</p>
      <MiuixButton v-if="error && !state" @click="load">{{ i18n.t('functional_button_retry') }}</MiuixButton>
    </div>
  </MiuixBottomSheet>
</template>

<style scoped>
.soter-local-sheet { display: grid; gap: 16px; padding: 0 4px 24px; }
.soter-note { margin: 0; color: var(--m-color-on-surface-variant-summary); font-size: 14px; line-height: 1.6; }
.soter-identity { display: grid; gap: 8px; padding: 18px; }
.soter-identity-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.soter-identity-heading strong { min-width: 0; overflow-wrap: anywhere; }
.soter-cpu-field { display: grid; gap: 10px; padding: 8px 12px; font-size: 14px; }
.soter-cpu-field input { box-sizing: border-box; width: 100%; min-height: 50px; padding: 12px;
  border: 1px solid var(--m-color-outline-variant); border-radius: 14px;
  background: var(--m-color-surface-container); color: inherit; font: inherit; }
.soter-error { margin: 0; color: var(--m-color-error); overflow-wrap: anywhere; }
</style>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  MiuixArrowPreference,
  MiuixCard,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
  MiuixSmallTitle,
  MiuixTopAppBar,
} from 'miuix-vue'
import { AddCircle, BankCards, Close, Lock, Replace, Reset, Update } from 'miuix-vue/icons'
import MiuixBottomSheet from './StableBottomSheet.vue'
import { i18n } from '../i18n'

export type ToolEvent =
  | 'openAppTargets'
  | 'installKeybox'
  | 'syncSecurityPatch'
  | 'restoreSecurityPatch'
  | 'spoofPif'
  | 'clearGmsCache'
  | 'repairRkp'
  | 'issueRkp'
  | 'openSoterLocal'

type BusyPatch = 'sync' | 'restore' | null
type SheetId = 'rkp' | 'patch'
type IconValue = typeof AddCircle | null

interface ToolAction {
  event: ToolEvent
  icon: IconValue
  title: string
  summary: string
}

interface ToolRow {
  key: string
  icon: IconValue
  title: string
  summary: string
  event?: ToolEvent
  sheet?: SheetId
}

const props = defineProps<{
  securityPatchBusy: BusyPatch
  maintenanceBusy: 'gms' | 'rkp' | null
  rkpIssuanceBusy: boolean
  securityPatch: string | null
}>()

const emit = defineEmits<{
  openAppTargets: []
  installKeybox: []
  syncSecurityPatch: []
  restoreSecurityPatch: []
  spoofPif: []
  clearGmsCache: []
  repairRkp: []
  issueRkp: []
  openSoterLocal: []
  'overlay-open': []
  'overlay-close': []
}>()

function runTool(event: ToolEvent): void {
  switch (event) {
    case 'openAppTargets': emit('openAppTargets'); break
    case 'installKeybox': emit('installKeybox'); break
    case 'syncSecurityPatch': emit('syncSecurityPatch'); break
    case 'restoreSecurityPatch': emit('restoreSecurityPatch'); break
    case 'spoofPif': emit('spoofPif'); break
    case 'clearGmsCache': emit('clearGmsCache'); break
    case 'repairRkp': emit('repairRkp'); break
    case 'issueRkp': emit('issueRkp'); break
    case 'openSoterLocal': emit('openSoterLocal'); break
  }
}

function tr(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const activeSheet = ref<SheetId | null>(null)
const sheetOpen = computed({
  get: () => activeSheet.value !== null,
  set: (open: boolean) => { if (!open) activeSheet.value = null },
})
// Keep the last sheet's content while the close animation plays.
const shownSheet = ref<SheetId>('rkp')

watch(activeSheet, (sheet, previous) => {
  if (sheet !== null) shownSheet.value = sheet
  if (sheet !== null && previous === null) emit('overlay-open')
  else if (sheet === null && previous !== null) emit('overlay-close')
})

defineExpose({ dismissOverlay: () => { activeSheet.value = null } })

const sheets: Record<SheetId, { title: string, actions: ToolAction[] }> = {
  rkp: {
    title: tr('tools_rkp', 'Remote key provisioning'),
    actions: [
      {
        event: 'repairRkp',
        icon: Reset,
        title: tr('tools_repair_rkp', 'Fix RKP'),
        summary: tr('tools_repair_rkp_desc', 'Run the vendor provisioning tool after confirming the persistent-write risk.'),
      },
      {
        event: 'issueRkp',
        icon: BankCards,
        title: tr('tools_issue_rkp', 'Issue local RKP Keybox'),
        summary: tr('tools_issue_rkp_desc', 'Use this device\'s RKP service to request a certificate for a locally generated key.'),
      },
    ],
  },
  patch: {
    title: tr('tools_security_patch', 'Security patch settings'),
    actions: [
      {
        event: 'syncSecurityPatch',
        icon: Update,
        title: tr('menu_sync_security_patch', 'Sync security patch'),
        summary: tr('tools_sync_patch_desc', 'Apply the latest Google security patch date. A reboot is required.'),
      },
      {
        event: 'restoreSecurityPatch',
        icon: Reset,
        title: tr('menu_restore_default_security_patch', 'Restore default security patch'),
        summary: tr('tools_restore_patch_desc', 'Restore the device default security patch date. A reboot is required.'),
      },
    ],
  },
}

const groups = computed<{ title: string, rows: ToolRow[] }[]>(() => [
  {
    title: tr('tools_app_management', 'App management'),
    rows: [{
      key: 'targets',
      event: 'openAppTargets',
      icon: AddCircle,
      title: tr('app_targets_title', 'Add package names'),
      summary: tr('tools_app_targets_desc', 'Choose which installed apps are routed through Oh My Keymint.'),
    }],
  },
  {
    title: tr('tools_keybox_attestation', 'Keybox & attestation'),
    rows: [
      {
        key: 'keybox',
        event: 'installKeybox',
        icon: Replace,
        title: tr('menu_replace_keybox', 'Change Keybox'),
        summary: tr('tools_keybox_desc', 'Choose a Keybox.xml file and install it for Oh My Keymint.'),
      },
      {
        key: 'rkp',
        sheet: 'rkp',
        icon: Lock,
        title: tr('tools_rkp', 'Remote key provisioning'),
        summary: tr('tools_rkp_desc', 'Fix RKP or issue a local RKP Keybox.'),
      },
      {
        key: 'soter',
        event: 'openSoterLocal',
        icon: BankCards,
        title: tr('soter_local_title', 'Local SOTER identities'),
        summary: tr('soter_local_tool_desc', 'Create random local identities and set app CPU-ID overrides.'),
      },
    ],
  },
  {
    title: tr('tools_play_integrity', 'Play Integrity'),
    rows: [
      {
        key: 'pif',
        event: 'spoofPif',
        icon: null,
        title: tr('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
        summary: tr('tools_pif_desc', 'Fetch and apply a Pixel fingerprint for Play Integrity.'),
      },
      {
        key: 'gms',
        event: 'clearGmsCache',
        icon: Reset,
        title: tr('tools_clear_gms_cache', 'Clear GMS cache'),
        summary: tr('tools_clear_gms_cache_desc', 'Clear Play services and Play Store caches, keep app data, then stop the specified processes.'),
      },
      {
        key: 'patch',
        sheet: 'patch',
        icon: Update,
        title: tr('tools_security_patch', 'Security patch settings'),
        summary: props.securityPatch
          ?? tr('tools_security_patch_desc', 'Sync or restore the reported security patch date.'),
      },
    ],
  },
])

function isBusy(event: ToolEvent): boolean {
  if (event === 'clearGmsCache' || event === 'repairRkp') return props.maintenanceBusy !== null
  if (event === 'issueRkp') return props.rkpIssuanceBusy
  if (event === 'syncSecurityPatch' || event === 'restoreSecurityPatch') {
    return props.securityPatchBusy !== null
  }
  return false
}

function isActiveBusy(event: ToolEvent): boolean {
  return (event === 'syncSecurityPatch' && props.securityPatchBusy === 'sync')
    || (event === 'restoreSecurityPatch' && props.securityPatchBusy === 'restore')
    || (event === 'clearGmsCache' && props.maintenanceBusy === 'gms')
    || (event === 'repairRkp' && props.maintenanceBusy === 'rkp')
    || (event === 'issueRkp' && props.rkpIssuanceBusy)
}

function rowActiveBusy(row: ToolRow): boolean {
  if (row.event) return isActiveBusy(row.event)
  return row.sheet ? sheets[row.sheet].actions.some(action => isActiveBusy(action.event)) : false
}

function rowDisabled(row: ToolRow): boolean {
  if (row.event) return isBusy(row.event)
  return row.sheet ? sheets[row.sheet].actions.every(action => isBusy(action.event)) : false
}

function onRow(row: ToolRow): void {
  if (row.sheet) activeSheet.value = row.sheet
  else if (row.event) runTool(row.event)
}

function onSheetAction(action: ToolAction): void {
  activeSheet.value = null
  runTool(action.event)
}
</script>

<template>
  <section class="app-page tools-page" aria-labelledby="tools-title">
    <MiuixTopAppBar :title="tr('tools_title', 'Tools')" />
    <h1 id="tools-title" class="page-large-title">{{ tr('tools_title', 'Tools') }}</h1>

    <section v-for="group in groups" :key="group.title" class="preference-section">
      <MiuixSmallTitle :text="group.title" />
      <MiuixCard class="preference-card" press-feedback="none">
        <MiuixArrowPreference
          v-for="row in group.rows"
          :key="row.key"
          :title="row.title"
          :summary="row.summary"
          :disabled="rowDisabled(row)"
          :hold-down="rowActiveBusy(row)"
          @click="onRow(row)"
        >
          <template #start>
            <span class="preference-icon">
              <MiuixProgressIndicator
                v-if="rowActiveBusy(row)"
                type="circular"
                :size="22"
                :stroke-width="2.5"
              />
              <MiuixIcon v-else-if="row.icon" :icon="row.icon" :size="23" />
              <svg v-else width="23" height="23" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="1.8" stroke-linecap="round"
                stroke-linejoin="round" aria-hidden="true">
                <path d="M3 11.5a9 9 0 0 1 18 0v2M3 15c-.1 1.5-.4 2.8-.9 4M5.5 17c.5-1.6.5-3.3.5-5.5a6 6 0 0 1 12 0c0 3.3-.5 6-1.7 8.5M6.5 20c1.7-2.5 2.5-5.4 2.5-8.5a3 3 0 0 1 6 0c0 3.8-.7 7-2.2 10M9.7 21.5c1.5-3 2.3-6.3 2.3-10M20.5 17c-.2 1-.5 2-1 3" />
              </svg>
            </span>
          </template>
        </MiuixArrowPreference>
      </MiuixCard>
    </section>

    <MiuixBottomSheet v-model="sheetOpen" :title="sheets[shownSheet].title">
      <template #start-action>
        <MiuixIconButton
          :aria-label="tr('functional_button_cancel', 'Cancel')"
          @click="activeSheet = null"
        >
          <MiuixIcon :icon="Close" :size="22" />
        </MiuixIconButton>
      </template>
      <div class="tool-sheet">
        <MiuixCard class="preference-card" press-feedback="none">
          <MiuixArrowPreference
            v-for="action in sheets[shownSheet].actions"
            :key="action.event"
            :title="action.title"
            :summary="action.summary"
            :disabled="isBusy(action.event)"
            :hold-down="isActiveBusy(action.event)"
            @click="onSheetAction(action)"
          >
            <template #start>
              <span class="preference-icon">
                <MiuixProgressIndicator
                  v-if="isActiveBusy(action.event)"
                  type="circular"
                  :size="22"
                  :stroke-width="2.5"
                />
                <MiuixIcon v-else-if="action.icon" :icon="action.icon" :size="23" />
              </span>
            </template>
          </MiuixArrowPreference>
        </MiuixCard>
      </div>
    </MiuixBottomSheet>
  </section>
</template>

<script setup lang="ts">
import {
  MiuixArrowPreference,
  MiuixCard,
  MiuixIcon,
  MiuixProgressIndicator,
  MiuixSmallTitle,
  MiuixTopAppBar,
} from 'miuix-vue'
import { AddCircle, BankCards, Lock, Replace, Reset, Update } from 'miuix-vue/icons'
import { i18n } from '../i18n'

export type ToolEvent =
  | 'openAppTargets'
  | 'installKeybox'
  | 'syncSecurityPatch'
  | 'restoreSecurityPatch'
  | 'openSoterBeta'
  | 'openSoterHal'
  | 'spoofPif'
  | 'clearGmsCache'
  | 'repairRkp'
  | 'issueRkp'

type BusyPatch = 'sync' | 'restore' | null

const props = defineProps<{
  securityPatchBusy: BusyPatch
  maintenanceBusy: 'gms' | 'rkp' | null
  rkpIssuanceBusy: boolean
}>()

const emit = defineEmits<{
  openAppTargets: []
  installKeybox: []
  syncSecurityPatch: []
  restoreSecurityPatch: []
  openSoterBeta: []
  openSoterHal: []
  spoofPif: []
  clearGmsCache: []
  repairRkp: []
  issueRkp: []
}>()

function runTool(event: ToolEvent): void {
  switch (event) {
    case 'openAppTargets': emit('openAppTargets'); break
    case 'installKeybox': emit('installKeybox'); break
    case 'syncSecurityPatch': emit('syncSecurityPatch'); break
    case 'restoreSecurityPatch': emit('restoreSecurityPatch'); break
    case 'openSoterBeta': emit('openSoterBeta'); break
    case 'openSoterHal': emit('openSoterHal'); break
    case 'spoofPif': emit('spoofPif'); break
    case 'clearGmsCache': emit('clearGmsCache'); break
    case 'repairRkp': emit('repairRkp'); break
    case 'issueRkp': emit('issueRkp'); break
  }
}

function tr(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const groups = [
  {
    title: tr('tools_app_management', 'App management'),
    items: [{
      event: 'openAppTargets' as const,
      icon: AddCircle,
      title: tr('app_targets_title', 'Add package names'),
      summary: tr('tools_app_targets_desc', 'Choose which installed apps are routed through Oh My Keymint.'),
    }],
  },
  {
    title: tr('tools_key_management', 'Key management'),
    items: [
      {
        event: 'installKeybox' as const,
        icon: Replace,
        title: tr('menu_replace_keybox', 'Change Keybox'),
        summary: tr('tools_keybox_desc', 'Choose a Keybox.xml file and install it for Oh My Keymint.'),
      },
      {
        event: 'openSoterBeta' as const,
        icon: Lock,
        title: tr('tools_soter_beta', 'Fix Tencent Soter Server (Testing)'),
        summary: tr('tools_soter_beta_desc', 'Experimental compatibility for Tencent SoterServer. Requires Zygisk Next.'),
      },
      {
        event: 'openSoterHal' as const,
        icon: BankCards,
        title: tr('tools_wechat_soter', 'Fix WeChat payment fingerprint'),
        summary: tr('tools_wechat_soter_desc', 'Configure the Qualcomm Soter service.'),
      },
      {
        event: 'repairRkp' as const,
        icon: Reset,
        title: tr('tools_repair_rkp', 'Fix RKP'),
        summary: tr('tools_repair_rkp_desc', 'Run the vendor provisioning tool after confirming the persistent-write risk.'),
      },
      {
        event: 'issueRkp' as const,
        icon: BankCards,
        title: tr('tools_issue_rkp', 'Issue local RKP Keybox'),
        summary: tr('tools_issue_rkp_desc', 'Use this device\'s RKP service to request a certificate for a locally generated key.'),
      },
    ],
  },
  {
    title: tr('tools_fingerprint_spoofing', 'Fingerprint spoofing'),
    items: [{
      event: 'spoofPif' as const,
      icon: null,
      title: tr('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
      summary: tr('tools_pif_desc', 'Fetch and apply a Pixel fingerprint for Play Integrity.'),
    }, {
      event: 'clearGmsCache' as const,
      icon: Reset,
      title: tr('tools_clear_gms_cache', 'Clear GMS cache'),
      summary: tr('tools_clear_gms_cache_desc', 'Clear Play services and Play Store caches, keep app data, then stop the specified processes.'),
    }],
  },
  {
    title: tr('tools_security_patch', 'Set security patch'),
    items: [
      {
        event: 'syncSecurityPatch' as const,
        icon: Update,
        title: tr('menu_sync_security_patch', 'Sync security patch'),
        summary: tr('tools_sync_patch_desc', 'Apply the latest Google security patch date. A reboot is required.'),
      },
      {
        event: 'restoreSecurityPatch' as const,
        icon: Reset,
        title: tr('menu_restore_default_security_patch', 'Restore default security patch'),
        summary: tr('tools_restore_patch_desc', 'Restore the device default security patch date. A reboot is required.'),
      },
    ],
  },
]

function isBusy(event: ToolEvent): boolean {
  if (event === 'clearGmsCache' || event === 'repairRkp') return props.maintenanceBusy !== null
  if (event === 'issueRkp') return props.rkpIssuanceBusy
  if (event === 'syncSecurityPatch') return props.securityPatchBusy !== null
  if (event === 'restoreSecurityPatch') return props.securityPatchBusy !== null
  return false
}

function isActiveBusy(event: ToolEvent): boolean {
  return (event === 'syncSecurityPatch' && props.securityPatchBusy === 'sync')
    || (event === 'restoreSecurityPatch' && props.securityPatchBusy === 'restore')
    || (event === 'clearGmsCache' && props.maintenanceBusy === 'gms')
    || (event === 'repairRkp' && props.maintenanceBusy === 'rkp')
    || (event === 'issueRkp' && props.rkpIssuanceBusy)
}
</script>

<template>
  <section class="app-page tools-page" aria-labelledby="tools-title">
    <MiuixTopAppBar id="tools-title" :title="tr('tools_title', 'Tools')" />

    <section v-for="group in groups" :key="group.title" class="preference-section">
      <MiuixSmallTitle :text="group.title" />
      <MiuixCard class="preference-card" press-feedback="none">
        <MiuixArrowPreference
          v-for="item in group.items"
          :key="item.event"
          :title="item.title"
          :summary="item.summary"
          :disabled="isBusy(item.event)"
          :hold-down="isActiveBusy(item.event)"
          @click="runTool(item.event)"
        >
          <template #start>
            <span class="preference-icon">
              <MiuixProgressIndicator
                v-if="isActiveBusy(item.event)"
                type="circular"
                :size="22"
                :stroke-width="2.5"
              />
              <MiuixIcon v-else-if="item.icon" :icon="item.icon" :size="23" />
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
  </section>
</template>

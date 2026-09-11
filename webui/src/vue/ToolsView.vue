<script setup lang="ts">
import {
  MiuixArrowPreference,
  MiuixCard,
  MiuixIcon,
  MiuixProgressIndicator,
  MiuixSmallTitle,
  MiuixTopAppBar,
} from 'miuix-vue'
import { AddCircle, Lock, Replace, Reset, Tune, Update } from 'miuix-vue/icons'
import { i18n } from '../i18n'

export type ToolEvent =
  | 'openAppTargets'
  | 'installKeybox'
  | 'syncSecurityPatch'
  | 'restoreSecurityPatch'
  | 'openAdbDisabler'
  | 'spoofPif'

type BusyPatch = 'sync' | 'restore' | null

const props = defineProps<{
  securityPatchBusy: BusyPatch
  adbBusy: boolean
}>()

const emit = defineEmits<{
  openAppTargets: []
  installKeybox: []
  syncSecurityPatch: []
  restoreSecurityPatch: []
  openAdbDisabler: []
  spoofPif: []
}>()

function runTool(event: ToolEvent): void {
  switch (event) {
    case 'openAppTargets': emit('openAppTargets'); break
    case 'installKeybox': emit('installKeybox'); break
    case 'syncSecurityPatch': emit('syncSecurityPatch'); break
    case 'restoreSecurityPatch': emit('restoreSecurityPatch'); break
    case 'openAdbDisabler': emit('openAdbDisabler'); break
    case 'spoofPif': emit('spoofPif'); break
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
        event: 'openAdbDisabler' as const,
        icon: Lock,
        title: tr('tools_adb_disabler', 'ADB Disabler'),
        summary: tr('tools_adb_disabler_desc', 'Disable developer options, USB debugging and OEM unlock at boot.'),
      },
    ],
  },
  {
    title: tr('tools_fingerprint_spoofing', 'Fingerprint spoofing'),
    items: [{
      event: 'spoofPif' as const,
      icon: Tune,
      title: tr('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
      summary: tr('tools_pif_desc', 'Fetch and apply a Pixel fingerprint for Play Integrity.'),
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
  if (event === 'openAdbDisabler') return props.adbBusy
  if (event === 'syncSecurityPatch') return props.securityPatchBusy !== null
  if (event === 'restoreSecurityPatch') return props.securityPatchBusy !== null
  return false
}

function isActiveBusy(event: ToolEvent): boolean {
  return (event === 'openAdbDisabler' && props.adbBusy)
    || (event === 'syncSecurityPatch' && props.securityPatchBusy === 'sync')
    || (event === 'restoreSecurityPatch' && props.securityPatchBusy === 'restore')
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
              <MiuixIcon v-else :icon="item.icon" :size="23" />
            </span>
          </template>
        </MiuixArrowPreference>
      </MiuixCard>
    </section>
  </section>
</template>

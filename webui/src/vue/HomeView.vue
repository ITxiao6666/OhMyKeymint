<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  MiuixBasicComponent,
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
  MiuixTopAppBar,
} from 'miuix-vue'
import { Copy, Delete, Info, Ok, Recent } from 'miuix-vue/icons'
import type {
  ActivityEntry,
  KeyboxLevel,
  KeyboxRevocationStatus,
  KeyboxSource,
} from '../cli'
import { i18n } from '../i18n'

export type ModuleStatus = 'loading' | 'ready' | 'error'
export type KeyboxStatus = 'loading' | 'bundled' | 'custom' | 'invalid' | 'error'
export type TeeStatus = 'loading' | 'normal' | 'error'
export type ActivityStatus = 'loading' | 'ready' | 'error'

const props = defineProps<{
  keyboxStatus: KeyboxStatus
  keyboxSource: KeyboxSource
  keyboxLevel: KeyboxLevel
  keyboxRevocation: KeyboxRevocationStatus
  teeStatus: TeeStatus
  securityPatch: string | null
  spoofedDevice: string | null | undefined
  activities: ActivityEntry[]
  activityStatus: ActivityStatus
  activityClearBusy: boolean
}>()

const emit = defineEmits<{
  clearActivities: []
}>()

const activitiesExpanded = ref(false)
const copiedActivity = ref<number | null>(null)

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

const visibleActivities = computed(() => (
  activitiesExpanded.value ? props.activities : props.activities.slice(0, 4)
))

function describeActivity(entry: ActivityEntry): { title: string, detail: string } {
  switch (entry.action) {
    case 'targets_saved':
      return {
        title: tr('prompt_saved_target', 'Config saved'),
        detail: tr('home_selected_apps', '%s apps selected', entry.detail),
      }
    case 'keybox_changed':
      return {
        title: tr('menu_replace_keybox', 'Change Keybox'),
        detail: tr('prompt_keybox_replaced', 'Keybox was changed and will reload automatically.'),
      }
    case 'widevine_installed':
      return {
        // Keep historical records readable after the retired vendor action was
        // removed.  Do not expose the old feature name or suggest that it is
        // still available in the current WebUI.
        title: tr('home_legacy_key_provisioning', 'Legacy key provisioning'),
        detail: tr(
          'home_legacy_key_provisioning_detail',
          'A legacy key-provisioning activity was recorded.',
        ),
      }
    case 'security_patch_synced':
      return {
        title: tr('menu_sync_security_patch', 'Sync security patch'),
        detail: tr(
          'prompt_security_patch_sync_complete',
          'Security patch synchronization complete for %s. Please reboot the device.',
          entry.detail,
        ),
      }
    case 'security_patch_restored':
      return {
        title: tr('menu_restore_default_security_patch', 'Restore default security patch'),
        detail: tr(
          'prompt_security_patch_restored_default',
          'Default security patch restored. Please reboot the device.',
        ),
      }
    case 'pif_enabled': {
      let model = entry.detail
      let securityPatch = ''
      try {
        const detail = JSON.parse(entry.detail) as { model?: unknown, securityPatch?: unknown }
        if (typeof detail.model === 'string') model = detail.model
        if (typeof detail.securityPatch === 'string') securityPatch = detail.securityPatch
      } catch {
        // Plain-text records created outside the current WebUI remain readable.
      }
      return {
        title: tr('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
        detail: tr(
          'prompt_pif_applied',
          'PIF fingerprint applied: %s, security patch %s.',
          model,
          securityPatch,
        ),
      }
    }
    case 'pif_disabled':
      return {
        title: tr('menu_spoof_pif_fingerprint', 'Spoof PIF fingerprint'),
        detail: tr('prompt_pif_disabled', 'PIF fingerprint spoofing disabled.'),
      }
    case 'adb_disabler_changed':
      return {
        title: tr('tools_adb_disabler', 'ADB Disabler'),
        detail: entry.detail === 'enabled'
          ? tr('prompt_adb_disabler_applied', 'ADB Disabler enabled.')
          : tr('prompt_adb_disabler_disabled', 'ADB Disabler disabled.'),
      }
  }
}

function relativeTime(timestamp: number): string {
  const elapsedSeconds = Math.max(0, Math.round(Date.now() / 1000 - timestamp))
  const formatter = new Intl.RelativeTimeFormat(i18n.lang, { numeric: 'auto' })
  if (elapsedSeconds < 60) return formatter.format(-elapsedSeconds, 'second')
  if (elapsedSeconds < 3600) return formatter.format(-Math.round(elapsedSeconds / 60), 'minute')
  if (elapsedSeconds < 86_400) return formatter.format(-Math.round(elapsedSeconds / 3600), 'hour')
  if (elapsedSeconds < 2_592_000) {
    return formatter.format(-Math.round(elapsedSeconds / 86_400), 'day')
  }
  if (elapsedSeconds < 31_536_000) {
    return formatter.format(-Math.round(elapsedSeconds / 2_592_000), 'month')
  }
  return formatter.format(-Math.round(elapsedSeconds / 31_536_000), 'year')
}

function absoluteTime(timestamp: number): string {
  return new Intl.DateTimeFormat(i18n.lang, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(timestamp * 1000))
}

async function copyActivity(entry: ActivityEntry): Promise<void> {
  const description = describeActivity(entry)
  try {
    await navigator.clipboard.writeText(
      `${description.title}\n${description.detail}\n${absoluteTime(entry.timestamp)}`,
    )
    copiedActivity.value = entry.timestamp
    window.setTimeout(() => {
      if (copiedActivity.value === entry.timestamp) copiedActivity.value = null
    }, 1200)
  } catch (error) {
    console.error('Unable to copy WebUI activity:', error)
  }
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

    <MiuixCard class="activity-card" press-feedback="none">
      <header class="activity-heading">
        <div>
          <h2>{{ tr('home_recent_activity', 'Recent activity') }}</h2>
          <span>{{ tr('home_activity_events', '%s events', activities.length) }}</span>
        </div>
        <MiuixIconButton
          :disabled="activityClearBusy || activityStatus === 'loading' || activities.length === 0"
          :aria-label="tr('home_activity_clear', 'Clear activity')"
          :title="tr('home_activity_clear', 'Clear activity')"
          @click="emit('clearActivities')"
        >
          <MiuixProgressIndicator
            v-if="activityClearBusy"
            type="circular"
            :size="20"
            :stroke-width="2"
          />
          <MiuixIcon v-else :icon="Delete" :size="22" />
        </MiuixIconButton>
      </header>

      <div v-if="activityStatus !== 'ready' || activities.length === 0" class="activity-empty">
        <MiuixProgressIndicator
          v-if="activityStatus === 'loading'"
          type="circular"
          :size="24"
          :stroke-width="2.5"
        />
        <MiuixIcon v-else :icon="activityStatus === 'error' ? Info : Recent" :size="24" />
        <span>
          {{ activityStatus === 'error'
            ? tr('home_activity_load_error', 'Unable to load activity')
            : activityStatus === 'loading'
              ? tr('home_status_loading', 'Checking')
              : tr('home_activity_empty', 'No activity yet') }}
        </span>
      </div>

      <ol v-else class="activity-list">
        <li v-for="entry in visibleActivities" :key="`${entry.timestamp}-${entry.action}`">
          <MiuixBasicComponent
            :title="describeActivity(entry).title"
            :summary="describeActivity(entry).detail"
          >
            <template #end>
              <MiuixIconButton
                :aria-label="tr('home_activity_copy', 'Copy activity')"
                :title="tr('home_activity_copy', 'Copy activity')"
                @click.stop="copyActivity(entry)"
              >
                <MiuixIcon :icon="copiedActivity === entry.timestamp ? Ok : Copy" :size="19" />
              </MiuixIconButton>
            </template>
            <template #bottom>
              <time :datetime="new Date(entry.timestamp * 1000).toISOString()" :title="absoluteTime(entry.timestamp)">
                {{ relativeTime(entry.timestamp) }}
              </time>
            </template>
          </MiuixBasicComponent>
        </li>
      </ol>

      <MiuixButton
        v-if="activities.length > 4"
        class="activity-toggle"
        @click="activitiesExpanded = !activitiesExpanded"
      >
        {{ activitiesExpanded
          ? tr('home_activity_show_less', 'Show less')
          : tr('home_activity_show_all', 'Show all (%s)', activities.length) }}
      </MiuixButton>
    </MiuixCard>
  </section>
</template>

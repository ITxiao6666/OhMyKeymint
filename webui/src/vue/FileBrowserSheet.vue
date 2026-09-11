<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import {
  MiuixBasicComponent,
  MiuixBottomSheet,
  MiuixButton,
  MiuixCard,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
} from 'miuix-vue'
import { Back, File, Folder, Import } from 'miuix-vue/icons'
import type { FileSelector } from '../file_selector/file_selector'
import { i18n } from '../i18n'

const props = defineProps<{ selector: FileSelector }>()
const revision = ref(0)
const unsubscribe = props.selector.subscribe(() => { revision.value++ })
const state = computed(() => {
  void revision.value
  return {
    open: props.selector.open,
    entries: props.selector.entries,
    loading: props.selector.loading,
    status: props.selector.status,
    path: props.selector.currentPath,
    canGoBack: props.selector.canGoBack,
  }
})
onBeforeUnmount(unsubscribe)
</script>

<template>
  <MiuixBottomSheet
    :model-value="state.open"
    :title="i18n.t('replace_keybox_storage_root')"
    :allow-dismiss="!state.loading"
    :close-on-click-modal="!state.loading"
    @update:model-value="value => { if (!value) selector.cancel() }"
  >
    <template #start-action>
      <MiuixIconButton
        :disabled="state.loading || !state.canGoBack"
        :aria-label="i18n.t('replace_keybox_storage_parent')"
        @click="selector.navigateBack()"
      >
        <MiuixIcon :icon="Back" :size="22" />
      </MiuixIconButton>
    </template>
    <template #end-action>
      <MiuixIconButton
        :disabled="state.loading"
        :aria-label="i18n.t('replace_keybox_open_system')"
        @click="selector.openWithAnotherApp()"
      >
        <MiuixIcon :icon="Import" :size="22" />
      </MiuixIconButton>
    </template>
    <div class="file-browser">
      <div class="file-path" dir="ltr">{{ state.path }}</div>
      <div v-if="state.loading" class="file-status" role="status">
        <MiuixProgressIndicator type="circular" :size="28" :stroke-width="2.5" />
        <span>{{ state.status }}</span>
      </div>
      <template v-else>
        <div
          v-if="state.status"
          class="file-status"
          :class="{ 'file-status--error': state.entries.length > 0 }"
          role="status"
        >
          {{ state.status }}
        </div>
        <div v-if="state.entries.length === 0 && !state.status" class="file-status" role="status">
          {{ i18n.t('replace_keybox_storage_empty') }}
        </div>
        <MiuixCard v-if="state.entries.length > 0" class="file-list" press-feedback="none">
          <MiuixBasicComponent
            v-for="entry in state.entries"
            :key="entry.name"
            :title="entry.name"
            clickable
            @click="selector.activate(entry)"
          >
            <template #start><MiuixIcon :icon="entry.isDirectory ? Folder : File" :size="23" /></template>
          </MiuixBasicComponent>
        </MiuixCard>
      </template>
      <MiuixButton class="file-cancel" @click="selector.cancel()">{{ i18n.t('functional_button_cancel') }}</MiuixButton>
    </div>
  </MiuixBottomSheet>
</template>

<style scoped>
.file-browser { min-height: min(58vh, 480px); display: flex; flex-direction: column; gap: 10px; padding-bottom: max(18px, env(safe-area-inset-bottom)); }
.file-path { overflow-wrap: anywhere; color: var(--m-color-on-surface-variant-summary); font-size: var(--m-text-body2-size); }
.file-list { flex: 1; min-height: 0; }
.file-status { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; color: var(--m-color-on-surface-variant-summary); text-align: center; }
.file-status--error { flex: none; min-height: 32px; color: var(--m-color-error); }
.file-cancel { width: 100%; flex: none; }
</style>

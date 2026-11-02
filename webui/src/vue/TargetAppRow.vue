<script setup lang="ts">
import { ref, watch } from 'vue'
import { MiuixCheckboxPreference, MiuixIcon } from 'miuix-vue'
import { All } from 'miuix-vue/icons'

const props = defineProps<{
  packageName: string
  appName: string
  selected: boolean
  disabled: boolean
}>()

const emit = defineEmits<{
  select: [selected: boolean]
}>()

// Keep image decoding feedback local to this row. Updating a shared icon map
// would invalidate every installed-app row each time one icon finishes loading.
const iconLoaded = ref(false)
watch(() => props.packageName, () => { iconLoaded.value = false })
</script>

<template>
  <div class="target-app-row">
    <MiuixCheckboxPreference
      :model-value="selected"
      :disabled="disabled"
      :title="appName"
      :summary="packageName"
      location="end"
      @update:model-value="emit('select', $event)"
    >
      <template #start>
        <span class="app-icon-frame" :class="{ 'app-icon-frame--loaded': iconLoaded }">
          <img
            class="app-icon"
            :src="`ksu://icon/${packageName}`"
            :alt="appName"
            loading="lazy"
            decoding="async"
            draggable="false"
            @load="iconLoaded = true"
            @error="iconLoaded = false"
          >
          <MiuixIcon v-if="!iconLoaded" class="app-icon-fallback" :icon="All" :size="24" />
        </span>
      </template>
    </MiuixCheckboxPreference>
  </div>
</template>

<style scoped>
.target-app-row {
  display: flex;
  align-items: stretch;
  min-width: 0;
  border-radius: 22px;
  overflow: hidden;
  background: var(--m-color-surface-container);
}

.target-app-row :deep(.m-basic-component) {
  flex: 1;
  min-width: 0;
  min-height: 74px;
  padding: 12px 14px;
  border-radius: 0;
  overflow: hidden;
  background: transparent;
}

.app-icon-frame {
  position: relative;
  box-sizing: border-box;
  display: inline-flex;
  flex: none;
  align-items: center;
  justify-content: center;
  width: 42px;
  height: 42px;
  overflow: hidden;
  border-radius: 50%;
  color: var(--m-color-on-tertiary-container);
  background: var(--m-color-tertiary-container);
}

.app-icon {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  object-fit: cover;
  opacity: 0;
}

.app-icon-frame--loaded { background: transparent; }
.app-icon-frame--loaded .app-icon { opacity: 1; }
.app-icon-fallback { opacity: .8; }
</style>

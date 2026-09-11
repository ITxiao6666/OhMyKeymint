<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { ComponentPublicInstance, ComputedRef } from 'vue'
import {
  MiuixBottomSheet,
  MiuixButton,
  MiuixCard,
  MiuixCheckboxPreference,
  MiuixFloatingActionButton,
  MiuixIcon,
  MiuixIconButton,
  MiuixProgressIndicator,
  MiuixSearchBar,
  MiuixTabRow,
  MiuixTopAppBar,
} from 'miuix-vue'
import {
  AddCircle,
  All,
  Back,
  Clear,
  Close,
  More,
  Ok,
  Refresh,
  SelectAll,
} from 'miuix-vue/icons'
import type { AppList, SelectableAppEntry, SelectionFilter } from '../app_list/app_list'
import { i18n } from '../i18n'

interface Props {
  appList: AppList
  loading?: boolean
  applyEnabled?: boolean
}

interface SearchBarInstance extends ComponentPublicInstance {
  $el: HTMLElement
}

type IconState = 'loading' | 'loaded' | 'error'

const props = withDefaults(defineProps<Props>(), {
  loading: false,
  applyEnabled: true,
})

const emit = defineEmits<{
  close: []
  apply: []
  refresh: []
  'overlay-open': []
  'overlay-close': []
}>()

function translate(key: string, fallback: string): string {
  const value = i18n.t(key)
  return value === key ? fallback : value
}

const FILTERS: readonly SelectionFilter[] = ['all', 'selected', 'unselected']
const filterLabels = [
  translate('filter_all', 'All'),
  translate('filter_selected', 'Selected'),
  translate('filter_unselected', 'Not selected'),
]

const revision = ref(props.appList.revision)
const searchQuery = ref('')
const searchExpanded = ref(false)
const filterIndex = ref(0)
const menuOpen = ref(false)
const systemSheetOpen = ref(false)
const systemSearchQuery = ref('')
const systemSelection = ref(new Set<string>())
const iconStates = ref<Record<string, IconState>>({})
const searchBar = ref<SearchBarInstance | null>(null)

// A menu followed by the system sheet is one overlay in the parent's history.
// Watching the combined state also avoids closing a second layer on Android Back.
watch(() => menuOpen.value || systemSheetOpen.value, open => {
  if (open) emit('overlay-open')
  else emit('overlay-close')
})

const unsubscribe = props.appList.subscribe(snapshot => {
  revision.value = snapshot.revision
})

const activeFilter = computed<SelectionFilter>(() => FILTERS[filterIndex.value] ?? 'all')
const targetEntries = computed(() => {
  void revision.value
  return props.appList.getTargetEntries(searchQuery.value, activeFilter.value)
})
const systemEntries = computed(() => {
  void revision.value
  return props.appList.getSystemEntries(systemSearchQuery.value)
})

// MIUIX preferences include animated controls. Mount a small batch per paint so
// hundreds of installed packages cannot block the sheet or navigation animation.
function batchedEntries(
  entries: ComputedRef<SelectableAppEntry[]>,
  enabled: ComputedRef<boolean>,
): ComputedRef<SelectableAppEntry[]> {
  const count = ref(0)
  let frame = 0
  let timer = 0
  let generation = 0
  const cancel = () => {
    generation++
    cancelAnimationFrame(frame)
    clearTimeout(timer)
  }
  watch([entries, enabled], ([items, active]) => {
    cancel()
    if (!active) {
      count.value = 0
      return
    }
    count.value = Math.min(Math.max(count.value, 16), items.length)
    const currentGeneration = generation
    const append = () => {
      if (currentGeneration !== generation || count.value >= items.length) return
      frame = requestAnimationFrame(() => {
        timer = window.setTimeout(() => {
          if (currentGeneration !== generation) return
          count.value = Math.min(count.value + 16, items.length)
          append()
        }, 0)
      })
    }
    append()
  }, { immediate: true })
  onBeforeUnmount(cancel)
  return computed(() => entries.value.slice(0, count.value))
}

const renderedTargetEntries = batchedEntries(targetEntries, computed(() => !props.loading))
const renderedSystemEntries = batchedEntries(
  systemEntries,
  computed(() => systemSheetOpen.value && !props.loading),
)

function iconState(packageName: string): IconState {
  return iconStates.value[packageName] ?? 'loading'
}

function setIconState(packageName: string, state: IconState): void {
  if (iconStates.value[packageName] === state) return
  iconStates.value[packageName] = state
}

function setSelected(entry: SelectableAppEntry, selected: boolean): void {
  if (props.loading || menuOpen.value) return
  props.appList.setSelected(entry.packageName, selected)
}

function selectAll(): void {
  menuOpen.value = false
  props.appList.selectAll()
}

function deselectAll(): void {
  menuOpen.value = false
  props.appList.deselectAll()
}

function refresh(): void {
  menuOpen.value = false
  emit('refresh')
}

function apply(): void {
  if (!props.loading && props.applyEnabled) emit('apply')
}

function focusSearch(): void {
  searchExpanded.value = true
  requestAnimationFrame(() => {
    searchBar.value?.$el.querySelector<HTMLInputElement>('input[type="search"]')?.focus()
  })
}

function openSystemApps(): void {
  menuOpen.value = false
  systemSearchQuery.value = ''
  systemSelection.value = new Set(
    props.appList.getSystemEntries().filter(entry => entry.selected).map(entry => entry.packageName),
  )
  systemSheetOpen.value = true
}

function setSystemSelected(packageName: string, selected: boolean): void {
  const nextSelection = new Set(systemSelection.value)
  if (selected) nextSelection.add(packageName)
  else nextSelection.delete(packageName)
  systemSelection.value = nextSelection
}

function saveSystemApps(): void {
  if (props.loading) return
  props.appList.applySystemAppSelection([...systemSelection.value])
  systemSheetOpen.value = false
}

function closeSystemApps(): void {
  systemSheetOpen.value = false
}

function dismissOverlay(): boolean {
  if (systemSheetOpen.value) {
    closeSystemApps()
    return true
  }
  if (menuOpen.value) {
    menuOpen.value = false
    return true
  }
  return false
}

onBeforeUnmount(() => {
  unsubscribe()
})

defineExpose({
  focusSearch,
  selectAll,
  deselectAll,
  refresh,
  apply,
  openSystemApps,
  dismissOverlay,
})
</script>

<template>
  <section class="targets-view" aria-labelledby="targets-view-title">
    <div v-if="menuOpen" class="targets-menu-scrim" @click="menuOpen = false" />
    <div class="targets-top-bar">
      <MiuixTopAppBar
        id="targets-view-title"
        :title="translate('app_targets_title', 'Add package names')"
        color="transparent"
      >
        <template #navigation>
          <MiuixIconButton
            :aria-label="translate('functional_button_back', 'Back')"
            @click="emit('close')"
          >
            <MiuixIcon :icon="Back" />
          </MiuixIconButton>
        </template>

        <template #actions>
          <div class="targets-menu">
            <MiuixIconButton
              class="targets-menu-toggle"
              :hold-down="menuOpen"
              :aria-label="translate('menu_more_options', 'More options')"
              aria-haspopup="menu"
              :aria-expanded="menuOpen"
              @click.stop="menuOpen = !menuOpen"
            >
              <MiuixIcon :icon="More" />
            </MiuixIconButton>

            <Transition name="targets-menu">
              <MiuixCard v-if="menuOpen" class="targets-menu-popup" role="menu">
                <MiuixButton role="menuitem" @click="selectAll">
                  <MiuixIcon :icon="SelectAll" :size="21" />
                  <span>{{ translate('menu_select_all', 'Select all') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" @click="deselectAll">
                  <MiuixIcon :icon="Clear" :size="21" />
                  <span>{{ translate('menu_deselect_all', 'Deselect all') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" :disabled="loading" @click="refresh">
                  <MiuixIcon :icon="Refresh" :size="21" />
                  <span>{{ translate('menu_refresh', 'Refresh') }}</span>
                </MiuixButton>
                <MiuixButton role="menuitem" @click="openSystemApps">
                  <MiuixIcon :icon="AddCircle" :size="21" />
                  <span>{{ translate('menu_add_system_app', 'Add System App') }}</span>
                </MiuixButton>
              </MiuixCard>
            </Transition>
          </div>
        </template>
      </MiuixTopAppBar>

      <MiuixSearchBar
        ref="searchBar"
        v-model="searchQuery"
        v-model:expanded="searchExpanded"
        :label="translate('search_bar_search_placeholder', 'Search')"
        :cancel-text="translate('functional_button_cancel', 'Cancel')"
        @focusin="menuOpen = false"
      />

      <div class="targets-filter" :aria-label="translate('app_targets_filter_aria', 'Filter apps')">
        <MiuixTabRow
          contour
          :model-value="filterIndex"
          :tabs="filterLabels"
          @update:model-value="filterIndex = $event; menuOpen = false"
        />
      </div>
    </div>

    <main class="targets-content" :aria-busy="loading">
      <div v-if="loading" class="targets-loading" role="status">
        <MiuixProgressIndicator type="circular" :size="34" />
        <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
      </div>

      <MiuixCard v-else-if="targetEntries.length > 0" class="targets-list">
        <MiuixCheckboxPreference
          v-for="entry in renderedTargetEntries"
          v-memo="[entry.selected, entry.appName, iconState(entry.packageName)]"
          :key="entry.packageName"
          :model-value="entry.selected"
          :title="entry.appName"
          :summary="entry.packageName"
          location="end"
          @update:model-value="setSelected(entry, $event)"
        >
          <template #start>
            <span class="app-icon-frame" :class="`app-icon-frame--${iconState(entry.packageName)}`">
              <img
                class="app-icon"
                :src="`ksu://icon/${entry.packageName}`"
                :alt="entry.appName"
                loading="lazy"
                decoding="async"
                draggable="false"
                @load="setIconState(entry.packageName, 'loaded')"
                @error="setIconState(entry.packageName, 'error')"
              >
              <MiuixIcon
                v-if="iconState(entry.packageName) !== 'loaded'"
                class="app-icon-fallback"
                :icon="All"
                :size="24"
              />
            </span>
          </template>
        </MiuixCheckboxPreference>
        <div v-if="renderedTargetEntries.length < targetEntries.length" class="app-list-batch-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="24" />
          <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
        </div>
      </MiuixCard>

      <div v-else class="targets-empty">
        <MiuixIcon :icon="All" :size="34" />
        <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
      </div>
    </main>

    <MiuixFloatingActionButton
      class="targets-apply"
      :disabled="loading || !applyEnabled"
      :aria-label="translate('functional_button_apply', 'Apply')"
      :title="translate('functional_button_apply', 'Apply')"
      @click="apply"
    >
      <MiuixProgressIndicator
        v-if="loading"
        type="circular"
        :size="27"
        :stroke-width="3"
      />
      <MiuixIcon v-else :icon="Ok" />
    </MiuixFloatingActionButton>

    <MiuixBottomSheet
      v-model="systemSheetOpen"
      :title="translate('add_system_app_title', 'Add System App')"
    >
      <template #start-action>
        <MiuixIconButton
          :aria-label="translate('functional_button_cancel', 'Cancel')"
          @click="closeSystemApps"
        >
          <MiuixIcon :icon="Close" />
        </MiuixIconButton>
      </template>
      <template #end-action>
        <MiuixButton type="primary" :disabled="loading" @click="saveSystemApps">
          {{ translate('functional_button_save', 'Save') }}
        </MiuixButton>
      </template>

      <div class="system-app-sheet">
        <MiuixSearchBar
          v-model="systemSearchQuery"
          :label="translate('search_bar_search_placeholder', 'Search')"
          :cancel-text="translate('functional_button_cancel', 'Cancel')"
        />

        <div v-if="loading" class="system-app-loading" role="status">
          <MiuixProgressIndicator type="circular" :size="32" />
        </div>

        <MiuixCard v-else-if="systemEntries.length > 0" class="system-app-list">
          <MiuixCheckboxPreference
            v-for="entry in renderedSystemEntries"
            v-memo="[systemSelection.has(entry.packageName), entry.appName, iconState(entry.packageName)]"
            :key="entry.packageName"
            :model-value="systemSelection.has(entry.packageName)"
            :title="entry.appName"
            :summary="entry.packageName"
            location="end"
            @update:model-value="setSystemSelected(entry.packageName, $event)"
          >
            <template #start>
              <span class="app-icon-frame" :class="`app-icon-frame--${iconState(entry.packageName)}`">
                <img
                  class="app-icon"
                  :src="`ksu://icon/${entry.packageName}`"
                  :alt="entry.appName"
                  loading="lazy"
                  decoding="async"
                  draggable="false"
                  @load="setIconState(entry.packageName, 'loaded')"
                  @error="setIconState(entry.packageName, 'error')"
                >
                <MiuixIcon
                  v-if="iconState(entry.packageName) !== 'loaded'"
                  class="app-icon-fallback"
                  :icon="All"
                  :size="24"
                />
              </span>
            </template>
          </MiuixCheckboxPreference>
          <div v-if="renderedSystemEntries.length < systemEntries.length" class="app-list-batch-loading" role="status">
            <MiuixProgressIndicator type="circular" :size="24" />
            <span class="sr-only">{{ translate('home_status_loading', 'Checking') }}</span>
          </div>
        </MiuixCard>

        <div v-else class="targets-empty targets-empty--sheet">
          <MiuixIcon :icon="All" :size="32" />
          <p>{{ translate('app_targets_empty', 'No matching apps') }}</p>
        </div>
      </div>
    </MiuixBottomSheet>
  </section>
</template>

<style scoped>
.targets-view {
  position: relative;
  box-sizing: border-box;
  min-height: 100%;
  color: var(--m-color-on-background);
  background: var(--m-color-surface);
}

.targets-top-bar {
  position: sticky;
  z-index: 40;
  top: 0;
  box-sizing: border-box;
  padding-top: env(safe-area-inset-top, 0);
  /* Keep a solid fallback for older Android WebViews that do not implement
     CSS color-mix; the translucent value is then layered on when supported. */
  background: var(--m-color-surface);
  background: color-mix(in srgb, var(--m-color-surface) 92%, transparent);
  backdrop-filter: blur(18px) saturate(1.25);
}

.targets-top-bar :deep(.m-top-app-bar__nav) {
  padding-inline-start: max(8px, env(safe-area-inset-left, 0));
  padding-inline-end: 0;
}

.targets-top-bar :deep(.m-top-app-bar__actions) {
  padding-inline-start: 0;
  padding-inline-end: max(8px, env(safe-area-inset-right, 0));
}

.targets-menu {
  position: relative;
}

.targets-menu-scrim {
  position: fixed;
  z-index: 35;
  inset: 0;
}

.targets-menu-toggle {
  position: relative;
  z-index: 41;
}

.targets-menu-popup {
  position: absolute;
  z-index: 50;
  top: calc(100% + 6px);
  inset-inline-end: 0;
  width: max-content;
  min-width: 208px;
  padding: 6px;
  box-shadow: 0 10px 32px rgb(0 0 0 / 20%);
}

.targets-menu-popup :deep(.m-card) {
  gap: 2px;
  padding: 6px;
}

.targets-menu-popup :deep(.m-button) {
  width: 100%;
  min-height: 44px;
  justify-content: flex-start;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 12px;
  background: transparent;
  white-space: nowrap;
}

.targets-menu-enter-active,
.targets-menu-leave-active {
  transition: opacity 140ms ease, transform 180ms cubic-bezier(.2, .8, .2, 1);
  transform-origin: top right;
}

[dir='rtl'] .targets-menu-enter-active,
[dir='rtl'] .targets-menu-leave-active {
  transform-origin: top left;
}

.targets-menu-enter-from,
.targets-menu-leave-to {
  opacity: 0;
  transform: translateY(-5px) scale(.97);
}

.targets-filter {
  box-sizing: border-box;
  width: min(100%, 680px);
  margin: 7px auto 0;
  padding: 0 12px 10px;
}

.targets-filter :deep(.m-tab-row__scroll) {
  background: var(--m-color-surface-container-high);
}

.targets-content {
  box-sizing: border-box;
  width: min(100%, 680px);
  min-height: 240px;
  margin: 0 auto;
  padding: 8px 12px calc(96px + env(safe-area-inset-bottom, 0));
}

.targets-list,
.system-app-list {
  width: 100%;
}

.targets-list :deep(.m-basic-component),
.system-app-list :deep(.m-basic-component) {
  min-height: 68px;
  padding: 10px 14px;
}

.targets-list :deep(.m-basic-component__row),
.system-app-list :deep(.m-basic-component__row) {
  gap: 12px;
}

.targets-list :deep(.m-basic-component__center),
.system-app-list :deep(.m-basic-component__center) {
  overflow: hidden;
}

.targets-list :deep(.m-basic-component__center > *),
.system-app-list :deep(.m-basic-component__center > *) {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.targets-list :deep(.m-basic-component + .m-basic-component),
.system-app-list :deep(.m-basic-component + .m-basic-component) {
  border-top: 1px solid var(--m-color-divider-line);
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
  border-radius: 10px;
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

.app-icon-frame--loaded .app-icon {
  opacity: 1;
}

.app-icon-fallback {
  opacity: .8;
}

.app-list-batch-loading {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 64px;
}

.targets-loading,
.system-app-loading,
.targets-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 220px;
  color: var(--m-color-on-surface-variant-summary);
}

.targets-empty {
  flex-direction: column;
  gap: 10px;
  text-align: center;
}

.targets-empty p {
  margin: 0;
  font-size: 15px;
}

.targets-apply {
  position: fixed;
  z-index: 30;
  inset-inline-end: max(20px, calc(env(safe-area-inset-right, 0) + 14px));
  bottom: max(20px, calc(env(safe-area-inset-bottom, 0) + 14px));
}

.system-app-sheet {
  box-sizing: border-box;
  min-height: min(65vh, 520px);
  padding-bottom: max(18px, env(safe-area-inset-bottom, 0));
}

.system-app-sheet > :deep(.m-search-bar) {
  position: sticky;
  z-index: 2;
  top: 0;
  padding: 2px 0 12px;
  background: var(--m-color-background);
}

.targets-empty--sheet {
  min-height: 180px;
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

@media (max-width: 420px) {
  .targets-filter,
  .targets-content {
    padding-inline: 10px;
  }

  .targets-list :deep(.m-basic-component),
  .system-app-list :deep(.m-basic-component) {
    padding-inline: 12px;
  }

  .system-app-sheet {
    min-height: 68vh;
  }
}

@media (prefers-reduced-motion: reduce) {
  .targets-menu-enter-active,
  .targets-menu-leave-active {
    transition: none;
  }
}
</style>

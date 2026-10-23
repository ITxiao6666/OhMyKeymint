<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'

const props = withDefaults(defineProps<{
  modelValue: boolean
  title?: string
  allowDismiss?: boolean
  closeOnClickModal?: boolean
}>(), { title: '', allowDismiss: true, closeOnClickModal: true })
const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  close: []
}>()
const inner = ref<HTMLElement | null>(null)
let handle: HTMLElement | null = null
let pointer: number | null = null
let origin = 0
let distance = 0
let frame = 0
let scale = 1

function paint(): void {
  frame = 0
  if (inner.value) inner.value.style.transform = `translate3d(0, ${distance}px, 0)`
}

function release(): void {
  if (frame) cancelAnimationFrame(frame)
  frame = 0
  const id = pointer
  pointer = null
  if (id !== null && handle?.hasPointerCapture(id)) handle.releasePointerCapture(id)
  handle = null
}

function reset(): void {
  release()
  distance = 0
  if (inner.value) {
    inner.value.style.transition = ''
    inner.value.style.transform = ''
  }
}

function close(): void {
  if (!props.allowDismiss || !props.modelValue) return
  release()
  emit('update:modelValue', false)
  emit('close')
}

function start(event: PointerEvent): void {
  if (!event.isPrimary || event.button !== 0 || pointer !== null || !inner.value) return
  reset()
  handle = event.currentTarget as HTMLElement
  pointer = event.pointerId
  origin = event.clientY
  // Capture scaling once, before any gesture writes. Do not force layout on move.
  const height = inner.value.offsetHeight
  scale = height ? inner.value.getBoundingClientRect().height / height : 1
  inner.value.style.transition = 'none'
  handle.setPointerCapture(event.pointerId)
}

function move(event: PointerEvent): void {
  if (pointer !== event.pointerId) return
  const delta = Math.max(0, event.clientY - origin) / Math.max(.1, scale)
  distance = props.allowDismiss ? delta : delta * .1
  if (!frame) frame = requestAnimationFrame(paint)
}

function finish(event: PointerEvent): void {
  if (pointer !== event.pointerId) return
  move(event)
  if (event.type === 'pointerup' && props.allowDismiss && distance > 150) close()
  else reset()
}

watch(() => props.modelValue, () => reset())
watch(() => props.allowDismiss, allowed => { if (!allowed) reset() })
onBeforeUnmount(release)
</script>

<template>
  <Teleport to="body">
    <Transition name="omk-sheet" @after-leave="reset">
      <div v-if="modelValue" class="m-bottom-sheet__backdrop omk-stable-sheet"
        @click.self="closeOnClickModal && close()">
        <div class="m-bottom-sheet__sheet" role="dialog" aria-modal="true" :aria-label="title">
          <div ref="inner" class="m-bottom-sheet__inner">
            <div class="m-bottom-sheet__handle-area"
              @pointerdown="start" @pointermove="move" @pointerup="finish"
              @pointercancel="finish" @lostpointercapture="reset">
              <span class="m-bottom-sheet__handle" />
            </div>
            <div v-if="title || $slots['start-action'] || $slots['end-action']" class="m-bottom-sheet__title-row">
              <div class="m-bottom-sheet__action m-bottom-sheet__action--start"><slot name="start-action" /></div>
              <div class="m-bottom-sheet__title">{{ title }}</div>
              <div class="m-bottom-sheet__action m-bottom-sheet__action--end"><slot name="end-action" /></div>
            </div>
            <div class="m-bottom-sheet__content"><slot :close="close" /></div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.m-bottom-sheet__sheet {
  max-height: calc(100vh - var(--omk-top-inset, 0px) - 12px);
  max-height: calc(100dvh - var(--omk-top-inset, 0px) - 12px);
}
.m-bottom-sheet__title { font-size: var(--m-text-title4-size, 18px); font-weight: 500; }
.m-bottom-sheet__inner { transition: transform 280ms cubic-bezier(.2, .8, .2, 1); }
.omk-sheet-enter-active, .omk-sheet-leave-active { transition: opacity 240ms ease; }
.omk-sheet-enter-active .m-bottom-sheet__sheet,
.omk-sheet-leave-active .m-bottom-sheet__sheet { transition: transform 280ms cubic-bezier(.2, .8, .2, 1); }
.omk-sheet-enter-from, .omk-sheet-leave-to { opacity: 0; }
.omk-sheet-enter-from .m-bottom-sheet__sheet,
.omk-sheet-leave-to .m-bottom-sheet__sheet { transform: translate3d(0, 100%, 0); }
@media (prefers-reduced-motion: reduce) {
  .omk-stable-sheet, .omk-stable-sheet .m-bottom-sheet__sheet,
  .omk-stable-sheet .m-bottom-sheet__inner { transition: none; }
}
</style>

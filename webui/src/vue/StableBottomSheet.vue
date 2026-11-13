<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'

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
const sheetEl = ref<HTMLElement | null>(null)
let handle: HTMLElement | null = null
let pointer: number | null = null
let origin = 0
let distance = 0
let frame = 0
let scale = 1
// Downward speed of the current drag, in CSS pixels per millisecond. A short
// flick should dismiss even when it never reaches the distance threshold.
let lastY = 0
let lastAt = 0
let startedAt = 0
let velocity = 0
let restoreFocus: HTMLElement | null = null

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
  lastY = event.clientY
  lastAt = performance.now()
  startedAt = lastAt
  velocity = 0
  inner.value.style.transition = 'none'
  handle.setPointerCapture(event.pointerId)
}

function move(event: PointerEvent): void {
  if (pointer !== event.pointerId) return
  const now = performance.now()
  if (now - lastAt >= 8) {
    velocity = (event.clientY - lastY) / (now - lastAt)
    lastY = event.clientY
    lastAt = now
  }
  const delta = Math.max(0, event.clientY - origin) / Math.max(.1, scale)
  distance = props.allowDismiss ? delta : delta * .1
  if (!frame) frame = requestAnimationFrame(paint)
}

function finish(event: PointerEvent): void {
  if (pointer !== event.pointerId) return
  move(event)
  // Scale the distance threshold with the panel so a short sheet stays
  // dismissible, and treat a fast downward flick as a dismiss on its own.
  // Sparse move samples leave `velocity` at zero, so fall back to the average
  // speed of the whole gesture.
  const height = inner.value?.offsetHeight ?? 0
  // A panel that has not been laid out yet reports zero height; fall back to the
  // fixed threshold instead of dismissing on the first pixel of movement.
  const threshold = height > 0 ? Math.min(150, height * 0.25) : 150
  const elapsed = performance.now() - startedAt
  const speed = elapsed > 0 ? Math.max(velocity, distance / elapsed) : velocity
  const flick = speed > 0.75 && distance > 24
  if (event.type === 'pointerup' && props.allowDismiss && (distance > threshold || flick)) close()
  // A scroll claimed by the WebView cancels the pointer stream; keep a drag that
  // already passed the threshold dismissible instead of springing back.
  else if (event.type === 'pointercancel' && props.allowDismiss && distance > threshold) close()
  else reset()
}

watch(() => props.modelValue, open => {
  reset()
  if (open) {
    restoreFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    // Move focus into the dialog so keyboard and screen-reader users stay inside it.
    void nextTick(() => sheetEl.value?.focus())
  } else if (restoreFocus !== null) {
    const target = restoreFocus
    restoreFocus = null
    void nextTick(() => target.focus?.())
  }
})
watch(() => props.allowDismiss, allowed => { if (!allowed) reset() })
onBeforeUnmount(release)
</script>

<template>
  <Teleport to="body">
    <Transition name="omk-sheet" @after-leave="reset">
      <div v-if="modelValue" class="m-bottom-sheet__backdrop omk-stable-sheet"
        @click.self="closeOnClickModal && close()">
        <div ref="sheetEl" class="m-bottom-sheet__sheet" role="dialog" aria-modal="true"
          :aria-label="title" tabindex="-1">
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
/* The handle owns the whole vertical gesture here; without this the WebView can
   claim it as a scroll and cancel the pointer stream mid-drag. */
.m-bottom-sheet__handle-area { touch-action: none; }
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

#!/system/bin/sh
# Ommega (A-side) software Soter TA control and watchdog.
#
# The vendor AIDL HAL `vendor.qti.hardware.soter.ISoter/default` is a thin proxy
# over a Qualcomm TA in the secure world. When that applet cannot run, every
# Soter call fails and applications that use Soter as a local integrity probe
# read the device as tampered with. `soterta-svc` answers those calls from a
# software TA while the stock HAL is stopped; this script owns the switch.
#
#   soterta.sh              converge and keep converging (default, service.sh)
#   soterta.sh enable       write the flag and take over now
#   soterta.sh disable      drop the flag, stop the TA and start the stock HAL
#   soterta.sh status       print the state, one key=value per line
#   soterta.sh json         write and print the file the WebUI reads
#
# The WebUI normally reaches this script through the native bridge, which
# resolves the installed module path and invokes `enable` or `disable` after
# atomically saving the configuration. The watchdog itself remains the source
# of truth for the published runtime status below.
#
#   /data/misc/keystore/omk/data/soterta/enabled      present = software TA wanted
#   /data/misc/keystore/omk/data/soterta/status.json  published by the watchdog
#
# Default is OFF: without the flag the stock HAL keeps the service name and this
# script only publishes status. Rollback is always `start vendor.soter`.

MODDIR=${0%/*}
STATE_DIR=/data/adb/omk
TA_DIR=/data/misc/keystore/omk/data/soterta
FLAG=$TA_DIR/enabled
STATUS=$TA_DIR/status.json
PIDFILE=$TA_DIR/daemon.pid
MARKER=$TA_DIR/hal-taken-over
LOCK=$TA_DIR/lock
LAST_ID=$TA_DIR/last-id
ID_CHANGED=$TA_DIR/id-changed
ERRLOG=$TA_DIR/soterta.err
SERVICE=vendor.qti.hardware.soter.ISoter/default
HAL=vendor.soter
POLL=2
HEARTBEAT=30

g_enabled=0
g_running=0
g_pid=0
g_mode=-
g_owner=none
g_hal=unknown
g_device_id=-
g_ledger=0
g_failures=0
g_note=
g_id_changed=0
g_id_note=

log() {
  echo "soterta $(date +%H:%M:%S): $*"
}

# SOTERTA_DEBUG=1 makes every converge pass narrate its snapshot, which is what
# a stuck transition has to be diagnosed with.
debug() {
  [ -n "$SOTERTA_DEBUG" ] && log "debug: $*"
  return 0
}

# Only one converge may run at a time: the WebUI switch, a shell `enable` and the
# watchdog all converge, and two of them at once would stop each other's daemon.
#
# The holder records the pid along with the data that makes that pid mean
# something: pids are reused after a reboot, so "the pid is alive" alone cannot
# tell a live converge from an unrelated process that inherited the number. A
# lock left behind by a killed converge (or by a reboot in the middle of a pass)
# is broken instead of wedging every later pass -- the 2026-09-25 outage where
# the software TA was not taken over after a reboot was exactly that: the stale
# pid belonged to a media codec process.
LOCK_MAX_AGE=600

# Start time is field 22 of /proc/<pid>/stat. The comm field may contain spaces
# and parentheses, so everything up to the last ')' is dropped first.
proc_starttime() {
  sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}

lock_is_stale() {
  local hpid hboot hstart cur now mtime
  hpid=$(cat "$LOCK/pid" 2>/dev/null)
  hboot=$(cat "$LOCK/boot-id" 2>/dev/null)
  hstart=$(cat "$LOCK/starttime" 2>/dev/null)
  # A lock written before this metadata existed carries only the pid.
  [ -n "$hpid" ] && [ -n "$hboot" ] && [ -n "$hstart" ] || return 0
  # A lock from an earlier boot can never belong to a live converge.
  [ "$hboot" = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ] || return 0
  kill -0 "$hpid" 2>/dev/null || return 0
  # A zombie still answers kill -0, but its converge is gone.
  case "$(sed 's/.*) //' "/proc/$hpid/stat" 2>/dev/null | awk '{print $1}')" in
    Z | "") return 0 ;;
  esac
  # Same pid, different process: the number was reused.
  cur=$(proc_starttime "$hpid")
  [ -n "$cur" ] && [ "$cur" = "$hstart" ] || return 0
  # Last resort: a pass that holds the lock for ten minutes is not a pass.
  now=$(date +%s 2>/dev/null)
  mtime=$(stat -c %Y "$LOCK" 2>/dev/null)
  if [ -n "$now" ] && [ -n "$mtime" ] && [ $((now - mtime)) -gt "$LOCK_MAX_AGE" ]; then
    return 0
  fi
  return 1
}

acquire_lock() {
  local i=0 owner
  while :; do
    if mkdir "$LOCK" 2>/dev/null; then
      echo $$ > "$LOCK/pid"
      cat /proc/sys/kernel/random/boot_id > "$LOCK/boot-id" 2>/dev/null
      proc_starttime $$ > "$LOCK/starttime" 2>/dev/null
      return 0
    fi
    if lock_is_stale; then
      owner=$(cat "$LOCK/pid" 2>/dev/null)
      log "breaking stale lock (holder pid ${owner:-unknown})"
      mv "$LOCK" "$LOCK.stale.$$" 2>/dev/null || rm -rf "$LOCK"
      continue
    fi
    i=$((i + 1))
    [ "$i" -ge 50 ] && return 1
    sleep 0.2
  done
}

release_lock() {
  rm -rf "$LOCK" 2>/dev/null
}

find_binary() {
  for candidate in "$MODDIR/libs/arm64-v8a/soterta-svc" \
                   "$MODDIR/libs/x86_64/soterta-svc" \
                   "$MODDIR/soterta-svc" \
                   "$TA_DIR/soterta-svc" \
                   "$TA_DIR/soter-svc"; do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# A stray pid must never be mistaken for the daemon: the cmdline has to be the
# exact binary with the exact mode flag.
daemon_pid() {
  [ -f "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE" 2>/dev/null)
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  kill -0 "$pid" 2>/dev/null || return 1
  # Both spellings exist in the wild: the module packages soterta-svc while the
  # standalone build writes soter-svc.
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -E 'soterta?-svc --mode=' >/dev/null 2>&1 || return 1
  echo "$pid"
}

daemon_mode() {
  pid=$1
  case "$pid" in
    ''|0) echo -; return ;; # 0 is the "no daemon" placeholder used in status
  esac
  mode=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed -n 's/.*--mode=\([a-z]*\).*/\1/p')
  [ -n "$mode" ] && echo "$mode" || echo -
}

# A daemon that outlived its pidfile - a killed watchdog, a module update, the
# manual start from the docs - would otherwise keep the service name hostage and
# with it the stock HAL stopped, so every converge reaps those first.
stray_daemon_pids() {
  kept=$(daemon_pid)
  # The pattern must not start with "--": toybox pgrep would read it as an option.
  for pid in $(pgrep -f 'soterta?-svc' 2>/dev/null); do
    [ "$pid" = "$kept" ] && continue
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qE 'soterta?-svc --mode=' || continue
    echo "$pid"
  done
}

kill_stray_daemons() {
  found=$(stray_daemon_pids)
  [ -n "$found" ] || return 0
  for pid in $found; do
    kill -TERM "$pid" 2>/dev/null
  done
  sleep 0.5
  for pid in $(stray_daemon_pids); do
    kill -KILL "$pid" 2>/dev/null
  done
  log "stopped stray software TA instance(s): $(echo "$found" | tr '\n' ' ')"
  return 0
}

hal_state() {
  value=$(getprop init.svc.vendor.soter 2>/dev/null)
  [ -n "$value" ] && echo "$value" || echo unknown
}

# Older OMK releases stored the takeover and relay switches together as
# `enabled=true` in remote.conf. Migrate that state once so an upgrade keeps
# the software TA takeover active before the first WebUI save.
migrate_legacy_flag() {
  [ -f "$FLAG" ] && return 0
  [ -r "$TA_DIR/remote.conf" ] || return 0
  grep -Eq '^[[:space:]]*remote_enabled[[:space:]]*=' "$TA_DIR/remote.conf" 2>/dev/null && return 0
  if grep -Eq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*(true|1|yes|on)[[:space:]]*$' "$TA_DIR/remote.conf" 2>/dev/null; then
    date +%s > "$FLAG"
    chmod 0600 "$FLAG" 2>/dev/null
    log "migrated legacy Soter takeover switch"
  fi
}

# us = our daemon owns the service name, hal = the stock HAL does, none = nobody
#
# A live stock HAL is the last registrant even when our daemon is still alive:
# servicemanager replaces an entry, so the HAL can take the name back from under
# a daemon that never noticed, and calling that "us" would leave the device with
# a dead Soter while every status check says it is fine.
service_owner() {
  if ! service check "$SERVICE" 2>/dev/null | grep -q ': found$'; then
    echo none
    return
  fi
  if [ -n "$(daemon_pid)" ] && [ "$(hal_state)" != running ]; then
    echo us
  else
    echo hal
  fi
}

ledger_device_id() {
  [ -f "$TA_DIR/state.json" ] || return 1
  sed -n 's/^[[:space:]]*"cpu_id":[[:space:]]*"\([0-9a-f]\{32\}\)".*/\1/p' \
    "$TA_DIR/state.json" | head -n 1
}

stop_daemon() {
  pid=$(daemon_pid) || { rm -f "$PIDFILE"; return 0; }
  kill -TERM "$pid" 2>/dev/null
  i=0
  while [ "$i" -lt 20 ]; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.3
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null
    sleep 0.5
  fi
  rm -f "$PIDFILE"
}

# SoterServer caches its HAL proxy. Refresh it after each successful HAL
# replacement or restoration, not on every watchdog poll. A host started later
# has no old proxy.
# No force-stop or app-data deletion: Android can rebind the service normally.
restart_soter_host() {
  local host_pid host_name
  for host_pid in $(pidof com.tencent.soter.soterserver 2>/dev/null); do
    case "$host_pid" in ''|*[!0-9]*) continue ;; esac
    host_name=$(tr '\0' '\n' < "/proc/$host_pid/cmdline" 2>/dev/null | head -n 1)
    [ "$host_name" = com.tencent.soter.soterserver ] || continue
    if kill -TERM "$host_pid" 2>/dev/null; then
      log "restarting SoterServer pid=$host_pid to reconnect to the current Soter HAL"
    else
      log "could not restart SoterServer pid=$host_pid; reopen the Soter client"
    fi
  done
  return 0
}

# Start our daemon and wait until it owns the name.
spawn_daemon_and_wait() {
  binary=$(find_binary) || return 1
  # A live instance can have lost registration to the stock HAL. It must not
  # survive when the pidfile is replaced with the next instance's PID.
  stop_daemon
  mkdir -p "$TA_DIR"
  "$binary" --mode=answer >>"$ERRLOG" 2>&1 &
  pid=$!
  # Atomic: a half-written pidfile would read as "no daemon" to a concurrent pass.
  echo "$pid" > "$PIDFILE.tmp"
  mv "$PIDFILE.tmp" "$PIDFILE"
  i=0
  while [ "$i" -lt 20 ]; do
    if [ "$(service_owner)" = us ]; then
      restart_soter_host
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.3
    i=$((i + 1))
  done
  log "spawn failed: pid=$pid alive=$(kill -0 "$pid" 2>/dev/null && echo yes || echo no) owner=$(service_owner)"
  stop_daemon
  return 3
}

# Take the service name away from a live stock HAL. The HAL has to be up first,
# which is what §19 tested: stopping a live service is what frees the name.
start_daemon_takeover() {
  i=0
  while [ "$(hal_state)" != running ] && [ "$i" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
  done
  [ "$(hal_state)" = running ] || return 2
  stop "$HAL" 2>/dev/null
  : > "$MARKER" 2>/dev/null
  kill_stray_daemons
  i=0
  while [ "$(service_owner)" != none ] && [ "$i" -lt 20 ]; do
    sleep 0.3
    i=$((i + 1))
  done
  spawn_daemon_and_wait
}

# The name is already free: our daemon died while the HAL stayed stopped (we are
# the reason it is not running), so waiting for a live HAL would be wrong.
start_daemon_on_free_name() {
  kill_stray_daemons
  i=0
  while [ "$(service_owner)" != none ] && [ "$i" -lt 20 ]; do
    sleep 0.3
    i=$((i + 1))
  done
  spawn_daemon_and_wait
}

# Rollback: release the name first, then let init start the stock HAL. Starting
# the HAL while the name is still ours makes it register-fail and idle.
restore_hal() {
  stop_daemon
  kill_stray_daemons
  i=0
  while [ "$(service_owner)" = us ] && [ "$i" -lt 20 ]; do
    sleep 0.3
    i=$((i + 1))
  done
  if [ -f "$MARKER" ] || [ "$(hal_state)" = stopped ]; then
    start "$HAL" 2>/dev/null
  fi
  i=0
  while [ "$(hal_state)" != running ] && [ "$i" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
  done
  i=0
  while [ "$(service_owner)" = none ] && [ "$i" -lt 20 ]; do
    sleep 0.3
    i=$((i + 1))
  done
  if [ "$(hal_state)" = running ] && [ "$(service_owner)" = hal ]; then
    restart_soter_host
    rm -f "$MARKER"
    return 0
  fi
  log "stock HAL restoration is not confirmed; retaining takeover marker for retry"
  return 1
}

# Read-only snapshot; also safe to run while another converge holds the lock.
snapshot_state() {
  g_enabled=0
  # Software-TA takeover is independent of the relay configuration.
  [ -f "$FLAG" ] && g_enabled=1
  g_pid=$(daemon_pid) || g_pid=
  g_running=0
  [ -n "$g_pid" ] && g_running=1
  g_owner=$(service_owner)
  g_hal=$(hal_state)
  g_mode=$(daemon_mode "$g_pid")
  g_device_id=$(ledger_device_id) || g_device_id=-
  g_ledger=0
  [ -f "$TA_DIR/state.json" ] && g_ledger=1
  [ -n "$g_pid" ] || g_pid=0
}

# One convergence pass; fills the g_* state the status writers use.
converge() {
  # The snapshot comes first so a pass that cannot take the lock still reports
  # the real state instead of whatever the previous pass happened to leave.
  snapshot_state
  if ! acquire_lock; then
    log "another converge holds the lock; reporting the state as it is"
    return 0
  fi
  snapshot_state
  debug "pass: enabled=$g_enabled running=$g_running owner=$g_owner hal=$g_hal pidfile=$(cat "$PIDFILE" 2>/dev/null)"

  # Identity drift watch: the id must not move between passes, because every
  # client (and the relay-era registration) remembers this device by it. The
  # first id seen is recorded; a later mismatch is kept as a sticky marker.
  g_id_changed=0
  [ -f "$ID_CHANGED" ] && g_id_changed=1
  if [ "$g_device_id" != "-" ]; then
    if [ -f "$LAST_ID" ]; then
      last_id=$(cat "$LAST_ID" 2>/dev/null)
      if [ -n "$last_id" ] && [ "$last_id" != "$g_device_id" ]; then
        printf '%s -> %s\n' "$last_id" "$g_device_id" > "$ID_CHANGED"
        g_id_changed=1
        log "device id changed: $last_id -> $g_device_id"
      fi
    fi
    printf '%s\n' "$g_device_id" > "$LAST_ID"
  fi
  g_id_note=""
  [ -f "$ID_CHANGED" ] && g_id_note=$(cat "$ID_CHANGED" 2>/dev/null | tr -d '\n')

  # The stock HAL serving means nothing of ours is holding the name anymore.
  if [ "$g_owner" = hal ] && [ "$g_hal" = running ]; then
    rm -f "$MARKER"
  fi

  if [ "$g_enabled" = 1 ]; then
    if [ "$g_running" = 0 ] || [ "$g_owner" != us ]; then
      log "converge: wanted, running=$g_running owner=$g_owner hal=$g_hal"
      if [ "$g_hal" = running ]; then
        start_daemon_takeover
        started=$?
      else
        start_daemon_on_free_name
        started=$?
      fi
      if [ "$started" = 0 ]; then
        g_failures=0
        g_note=""
        log "converge: software TA is up"
      else
        case "$g_failures" in ''|*[!0-9]*) g_failures=0 ;; esac
        g_failures=$((g_failures + 1))
        restore_hal
        g_note="软件 TA 启动失败（第 $g_failures 次），已回滚到原厂 HAL / software TA failed to start (attempt $g_failures); rolled back to the stock HAL"
        log "$g_note (rc=$started)"
      fi
    fi
  elif [ "$g_owner" = us ] || [ -f "$MARKER" ] || [ -n "$(stray_daemon_pids)" ]; then
    if restore_hal; then
      g_failures=0
      g_note="已停用，原厂 HAL 已恢复 / disabled, stock HAL restored"
    else
      case "$g_failures" in ''|*[!0-9]*) g_failures=0 ;; esac
      g_failures=$((g_failures + 1))
      g_note="原厂 HAL 恢复尚未确认，将继续重试 / stock HAL restoration is not confirmed; retrying"
    fi
    log "$g_note"
  fi

  snapshot_state
  debug "done: enabled=$g_enabled running=$g_running owner=$g_owner hal=$g_hal"
  release_lock
  return 0
}

print_status() {
  echo "enabled=$g_enabled"
  echo "running=$g_running"
  echo "pid=$g_pid"
  echo "mode=$g_mode"
  echo "owner=$g_owner"
  echo "hal=$g_hal"
  echo "device_id=$g_device_id"
  echo "ledger=$g_ledger"
  echo "id_changed=$g_id_changed"
  [ -n "$g_id_note" ] && echo "id_note=$g_id_note"
  echo "failures=$g_failures"
  echo "updated=$(date +%s)"
  [ -n "$g_note" ] && echo "note=$g_note"
  return 0
}

# JSON is built by hand because the values are all ours: no quotes, no newlines.
write_status() {
  mkdir -p "$TA_DIR"
  body='{"enabled":'"$g_enabled"',"running":'"$g_running"',"pid":'"$g_pid"',"mode":"'"$g_mode"'","hal":"'"$g_hal"'","owner":"'"$g_owner"'","device_id":"'"$g_device_id"'","ledger":'"$g_ledger"',"id_changed":'"$g_id_changed"',"id_note":"'"$g_id_note"'","failures":'"$g_failures"',"updated":'"$(date +%s)"',"note":"'"$g_note"'"}'
  if [ "$body" != "$g_last_body" ] || [ $(( $(date +%s) - g_last_write )) -ge "$HEARTBEAT" ]; then
    printf '%s\n' "$body" > "$STATUS.tmp"
    chmod 0644 "$STATUS.tmp" 2>/dev/null
    mv "$STATUS.tmp" "$STATUS"
    g_last_body=$body
    g_last_write=$(date +%s)
  fi
  printf '%s\n' "$body"
}

supervise() {
  g_last_body=
  g_last_write=0
  trap 'log "watchdog stopping; rolling back"; restore_hal; write_status >/dev/null 2>&1; exit 0' INT TERM EXIT
  migrate_legacy_flag
  log "watchdog up (poll ${POLL}s, flag $FLAG)"
  while :; do
    # Publish the requested state before a long transition, so the WebUI never
    # has to wait for a takeover to finish before it can show the switch move.
    snapshot_state
    write_status >/dev/null
    converge
    snapshot_state
    write_status >/dev/null
    if [ "$g_failures" -gt 0 ]; then
      sleep 10
    else
      sleep "$POLL"
    fi
  done
}

case "$1" in
  enable)
    mkdir -p "$TA_DIR"
    date +%s > "$FLAG"
    chmod 0600 "$FLAG" 2>/dev/null
    snapshot_state
    write_status >/dev/null
    converge || { sleep 1; converge; }
    write_status >/dev/null
    print_status
    ;;
  disable)
    rm -f "$FLAG"
    snapshot_state
    write_status >/dev/null
    converge || { sleep 1; converge; }
    write_status >/dev/null
    print_status
    ;;
  reconcile)
    # Detached one-shot convergence. It never changes the desired-state flag;
    # if a newer enable arrives, converge follows that current flag instead.
    converge || { sleep 1; converge; }
    write_status >/dev/null
    snapshot_state
    if [ "$g_enabled" = 0 ] && [ "$g_running" = 0 ] \
        && [ "$g_owner" = hal ] && [ "$g_hal" = running ]; then
      exit 0
    fi
    exit 1
    ;;
  status)
    converge
    print_status
    ;;
  json)
    converge
    write_status
    ;;
  id)
    converge
    echo "id=$g_device_id"
    echo "ledger=$g_ledger"
    if [ -f "$TA_DIR/state.json" ]; then
      echo "sha256=$(sha256sum "$TA_DIR/state.json" | awk '{print $1}')"
    fi
    if [ -f "$ID_CHANGED" ]; then
      echo "id_changed=yes ($(cat "$ID_CHANGED" 2>/dev/null | tr -d '\n'))"
    else
      echo "id_changed=no"
    fi
    ;;
  ""|supervise)
    supervise
    ;;
  *)
    echo "usage: $0 [enable|disable|reconcile|status|json|id|supervise]" >&2
    exit 2
    ;;
esac

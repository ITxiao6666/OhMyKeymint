MODDIR=${0%/*}
STATE_DIR=/data/adb/omk

mkdir -p "$STATE_DIR"

pid_matches_script() {
  pid=$1
  script=$2
  [ -r "/proc/$pid/cmdline" ] || return 1
  cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
  echo "$cmdline" | grep -F "$script" >/dev/null 2>&1
}

start_daemon() {
  script=$1
  pidfile=$2

  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && pid_matches_script "$pid" "$script"; then
      return 0
    fi
    rm -f "$pidfile"
  fi

  sh "$script" &
  pid=$!
  echo $pid > "$pidfile"
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null || ! pid_matches_script "$pid" "$script"; then
    rm -f "$pidfile"
    return 1
  fi
  return 0
}

start_daemon "$MODDIR/daemon" "$STATE_DIR/keymint-daemon.pid"
start_daemon "$MODDIR/daemon-injector" "$STATE_DIR/injector-daemon.pid"


# Resolve the active root implementation's resetprop binary.
RESETPROP_BIN="$(command -v resetprop 2>/dev/null)"
if [ -z "$RESETPROP_BIN" ]; then
  if [ -x /data/adb/ksu/bin/resetprop ]; then
    RESETPROP_BIN=/data/adb/ksu/bin/resetprop
  elif [ -x /data/adb/magisk/resetprop ]; then
    RESETPROP_BIN=/data/adb/magisk/resetprop
  fi
fi

check_reset_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE=$("$RESETPROP_BIN" "$NAME")
  [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || "$RESETPROP_BIN" "$NAME" "$EXPECTED"
}

check_missing_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE=$("$RESETPROP_BIN" "$NAME")
  [ -z "$VALUE" ] && "$RESETPROP_BIN" "$NAME" "$EXPECTED"
}

check_missing_match_prop() {
  local NAME="$1"
  local EXPECTED="$2"
  local VALUE
  VALUE=$("$RESETPROP_BIN" "$NAME")
  [ -z "$VALUE" ] || [ "$VALUE" = "$EXPECTED" ] || "$RESETPROP_BIN" "$NAME" "$EXPECTED"
  [ -z "$VALUE" ] && "$RESETPROP_BIN" "$NAME" "$EXPECTED"
}

contains_reset_prop() {
  local NAME="$1"
  local CONTAINS="$2"
  local NEWVAL="$3"
  case "$("$RESETPROP_BIN" "$NAME")" in
    *"$CONTAINS"*) "$RESETPROP_BIN" "$NAME" "$NEWVAL" ;;
  esac
}

sleep 20

if [ -n "$RESETPROP_BIN" ]; then
  "$RESETPROP_BIN" -w sys.boot_completed 0
  check_missing_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
  check_reset_prop "ro.boot.vbmeta.avb_version" "1.2"
  check_reset_prop "ro.boot.vbmeta.hash_alg" "sha256"
  check_reset_prop "ro.boot.vbmeta.size" "19968"
  check_missing_match_prop "ro.boot.vbmeta.device_state" "locked"
  check_missing_match_prop "ro.boot.verifiedbootstate" "green"
  check_reset_prop "ro.boot.flash.locked" "1"
  check_reset_prop "ro.boot.veritymode" "enforcing"
  check_reset_prop "ro.boot.warranty_bit" "0"
  check_reset_prop "ro.warranty_bit" "0"
  check_reset_prop "ro.debuggable" "0"
  check_reset_prop "ro.force.debuggable" "0"
  check_reset_prop "ro.secure" "1"
  check_reset_prop "ro.adb.secure" "1"
  check_reset_prop "ro.build.type" "user"
  check_reset_prop "ro.build.tags" "release-keys"
  check_reset_prop "ro.vendor.boot.warranty_bit" "0"
  check_reset_prop "ro.vendor.warranty_bit" "0"
  check_missing_match_prop "vendor.boot.vbmeta.device_state" "locked"
  check_missing_match_prop "vendor.boot.verifiedbootstate" "green"
  check_reset_prop "sys.oem_unlock_allowed" "0"
  check_reset_prop "ro.secureboot.lockstate" "locked"
  check_reset_prop "ro.boot.realmebootstate" "green"
  check_reset_prop "ro.boot.realme.lockstate" "1"
  check_reset_prop "ro.crypto.state" "encrypted"

  # Hide adb debugging traces.
  "$RESETPROP_BIN" "sys.usb.adb.disabled" " "
  # Hide recovery boot mode.
  contains_reset_prop "ro.bootmode" "recovery" "unknown"
  contains_reset_prop "ro.boot.bootmode" "recovery" "unknown"
  contains_reset_prop "vendor.boot.bootmode" "recovery" "unknown"
fi

# Optional ADB Disabler configuration written by the WebUI. The file contains
# four lines (enabled, developer options, USB debugging, OEM unlock), each 0/1.
# Keep this parser deliberately strict: malformed or missing state is ignored.
ADB_DISABLER_CONFIG=/data/misc/keystore/omk/data/adb_disabler.conf
if [ -r "$ADB_DISABLER_CONFIG" ] && [ -n "$RESETPROP_BIN" ]; then
  SETTINGS_BIN=/system/bin/settings
  [ -x "$SETTINGS_BIN" ] || SETTINGS_BIN=settings
  ADB_LOCK=$(sed -n '1p' "$ADB_DISABLER_CONFIG" 2>/dev/null)
  ADB_DEV=$(sed -n '2p' "$ADB_DISABLER_CONFIG" 2>/dev/null)
  ADB_USB=$(sed -n '3p' "$ADB_DISABLER_CONFIG" 2>/dev/null)
  ADB_OEM=$(sed -n '4p' "$ADB_DISABLER_CONFIG" 2>/dev/null)
  # Reject trailing records as well as malformed values.  This prevents a
  # partially-written or hand-edited file from being treated as valid state.
  ADB_LINE_COUNT=$(wc -l < "$ADB_DISABLER_CONFIG" 2>/dev/null)
  ADB_LINE_COUNT=${ADB_LINE_COUNT##* }
  ADB_EXTRA=$(sed -n '5p' "$ADB_DISABLER_CONFIG" 2>/dev/null)
  if [ "$ADB_LINE_COUNT" = 4 ]; then
    case "$ADB_LOCK:$ADB_DEV:$ADB_USB:$ADB_OEM:$ADB_EXTRA" in
    1:0:0:0:|1:0:0:1:|1:0:1:0:|1:0:1:1:|1:1:0:0:|1:1:0:1:|1:1:1:0:|1:1:1:1:)
      if [ "$ADB_DEV" = 1 ]; then
        "$SETTINGS_BIN" put global development_settings_enabled 0 2>/dev/null
        "$RESETPROP_BIN" -n persist.sys.development_settings_enabled 0
        "$RESETPROP_BIN" -n ro.debuggable 0
        "$RESETPROP_BIN" -n ro.force.debuggable 0
      fi
      if [ "$ADB_USB" = 1 ]; then
        "$SETTINGS_BIN" put global adb_enabled 0 2>/dev/null
        "$RESETPROP_BIN" -n ro.adb.secure 1
        "$RESETPROP_BIN" -n persist.sys.usb.config mtp
        "$RESETPROP_BIN" -n sys.usb.config mtp
        "$RESETPROP_BIN" -n service.adb.root 0
        "$RESETPROP_BIN" -n init.svc.adbd stopped
        "$RESETPROP_BIN" -n init.svc_debug_pid.adbd ""
      fi
      if [ "$ADB_OEM" = 1 ]; then
        "$RESETPROP_BIN" -n sys.oem_unlock_allowed 0
        "$RESETPROP_BIN" -n ro.oem_unlock_supported 0
      fi
      ;;
    esac
  fi
fi

#Hide Lsposed Logd
setprop persist.logd.size ""
setprop persist.logd.size.crash ""
setprop persist.logd.size.system ""
setprop persist.logd.size.main ""

# Hide cloudphone detection.
if [ -n "$RESETPROP_BIN" ] && [ -n "$("$RESETPROP_BIN" ro.kernel.qemu)" ]; then
  "$RESETPROP_BIN" ro.kernel.qemu ""
fi

#!/system/bin/sh

MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/omk
LOG_DIR=$TARGET_DIR/logs
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
STATE_DIR=/data/adb/omk
SECURITY_PATCH_CONFIG=$TARGET_DIR/config.toml
SECURITY_PATCH_SNAPSHOT=$TARGET_DIR/data/security_patch_defaults.toml


mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"

mkdir -p "$LOG_DIR"
chmod 0770 "$LOG_DIR"
chown 1017:1017 "$LOG_DIR"

mkdir -p "$STATE_DIR"
rm -f "$STATE_DIR/keymint-daemon.pid" "$STATE_DIR/injector-daemon.pid"
rm -f "$STATE_DIR/restart.keymint" "$STATE_DIR/restart.injector" "$STATE_DIR/restart.all"

if [ ! -f "$TARGET_KEYBOX" ] && [ -f "$MODDIR/keybox.xml" ]; then
  cp "$MODDIR/keybox.xml" "$TARGET_KEYBOX"
fi

if [ ! -f "$TARGET_INJECTOR_CONFIG" ] && [ -f "$MODDIR/injector.toml" ]; then
  cp "$MODDIR/injector.toml" "$TARGET_INJECTOR_CONFIG"
fi

if [ -f "$TARGET_KEYBOX" ]; then
  chmod 0600 "$TARGET_KEYBOX"
  chown 1017:1017 "$TARGET_KEYBOX"
fi

if [ -f "$TARGET_INJECTOR_CONFIG" ]; then
  chmod 0600 "$TARGET_INJECTOR_CONFIG"
  chown 1017:1017 "$TARGET_INJECTOR_CONFIG"
fi

# Replay a WebUI synchronization before Android framework caches
# Build.VERSION.SECURITY_PATCH. Restore removes the snapshot and changes all
# four fields to auto, so it naturally skips this block on the next boot.
reapply_security_patch_early() (
  [ -r "$SECURITY_PATCH_CONFIG" ] || return 0
  [ -f "$SECURITY_PATCH_SNAPSHOT" ] || return 0
  grep -Eq '^[[:space:]]*version[[:space:]]*=[[:space:]]*1[[:space:]]*$' \
    "$SECURITY_PATCH_SNAPSHOT" 2>/dev/null || return 0

  PATCH_FIELDS=$(awk '
    BEGIN { in_trust = 0; security = ""; os = ""; vendor = ""; boot = "" }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      in_trust = ($0 ~ /^[[:space:]]*\[trust\][[:space:]]*$/)
      next
    }
    in_trust {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      key = line
      sub(/[[:space:]]*=.*/, "", key)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      if (key != "security_patch" && key != "os_patchlevel" \
        && key != "vendor_patchlevel" && key != "boot_patchlevel") next
      value = line
      sub(/^[^=]*=[[:space:]]*/, "", value)
      if (substr(value, 1, 1) != "\"") next
      value = substr(value, 2)
      quote = index(value, "\"")
      if (quote == 0) next
      value = substr(value, 1, quote - 1)
      if (key == "security_patch") security = value
      else if (key == "os_patchlevel") os = value
      else if (key == "vendor_patchlevel") vendor = value
      else if (key == "boot_patchlevel") boot = value
    }
    END {
      if (security != "" && os != "" && vendor != "" && boot != "")
        printf "%s %s %s %s\n", security, os, vendor, boot
    }
  ' "$SECURITY_PATCH_CONFIG" 2>/dev/null)
  [ -n "$PATCH_FIELDS" ] || return 0

  # The config writer emits date/auto tokens. Disable globbing while splitting
  # the four values so malformed input cannot expand filenames.
  set -f
  IFS=' '
  set -- $PATCH_FIELDS
  [ "$#" -eq 4 ] || return 0
  [ "$1" = "$2" ] && [ "$1" = "$3" ] && [ "$1" = "$4" ] || return 0
  case "$1" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) return 0 ;;
  esac
  PATCH_MONTH=${1#????-}
  PATCH_MONTH=${PATCH_MONTH%%-*}
  PATCH_DAY=${1##*-}
  case "$PATCH_MONTH" in
    01|02|03|04|05|06|07|08|09|10|11|12) ;;
    *) return 0 ;;
  esac
  case "$PATCH_DAY" in
    01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31) ;;
    *) return 0 ;;
  esac
  PATCH_DATE=$1

  RESETPROP_MODE=direct
  RESETPROP_BIN=
  for candidate in \
    /data/adb/ksu/bin/resetprop \
    /data/adb/magisk/resetprop \
    /data/adb/ap/bin/resetprop
  do
    if [ -x "$candidate" ]; then
      RESETPROP_BIN=$candidate
      break
    fi
  done
  if [ -z "$RESETPROP_BIN" ] && [ -x /data/adb/ksud ]; then
    RESETPROP_BIN=/data/adb/ksud
    RESETPROP_MODE=ksud
  elif [ -z "$RESETPROP_BIN" ] && [ -x /data/adb/apd ]; then
    RESETPROP_BIN=/data/adb/apd
    RESETPROP_MODE=apd
  fi
  if [ -z "$RESETPROP_BIN" ]; then
    RESETPROP_BIN=$(command -v resetprop 2>/dev/null)
  fi
  if [ -z "$RESETPROP_BIN" ]; then
    for candidate in /system_ext/bin/resetprop /system/bin/resetprop; do
      if [ -x "$candidate" ]; then
        RESETPROP_BIN=$candidate
        break
      fi
    done
  fi
  [ -n "$RESETPROP_BIN" ] || return 0

  if [ "$RESETPROP_MODE" = ksud ]; then
    "$RESETPROP_BIN" resetprop ro.vendor.build.security_patch "$PATCH_DATE" \
      >/dev/null 2>&1
    "$RESETPROP_BIN" resetprop ro.build.version.security_patch "$PATCH_DATE" \
      >/dev/null 2>&1
  elif [ "$RESETPROP_MODE" = apd ]; then
    "$RESETPROP_BIN" resetprop ro.vendor.build.security_patch "$PATCH_DATE" \
      >/dev/null 2>&1
    "$RESETPROP_BIN" resetprop ro.build.version.security_patch "$PATCH_DATE" \
      >/dev/null 2>&1
  else
    "$RESETPROP_BIN" ro.vendor.build.security_patch "$PATCH_DATE" >/dev/null 2>&1
    "$RESETPROP_BIN" ro.build.version.security_patch "$PATCH_DATE" >/dev/null 2>&1
  fi

  GETPROP_BIN=/system/bin/getprop
  [ -x "$GETPROP_BIN" ] || GETPROP_BIN=$(command -v getprop 2>/dev/null)
  if [ -n "$GETPROP_BIN" ]; then
    CURRENT_VENDOR=$("$GETPROP_BIN" ro.vendor.build.security_patch 2>/dev/null)
    CURRENT_SYSTEM=$("$GETPROP_BIN" ro.build.version.security_patch 2>/dev/null)
    if [ "$CURRENT_VENDOR" != "$PATCH_DATE" ] || [ "$CURRENT_SYSTEM" != "$PATCH_DATE" ]; then
      echo "[oh_my_keymint] unable to apply security patch $PATCH_DATE before framework startup" >&2
    fi
  fi
  return 0
)

reapply_security_patch_early || true

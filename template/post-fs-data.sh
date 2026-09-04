#!/system/bin/sh

MODDIR=${0%/*}
TARGET_DIR=/data/misc/keystore/omk
DATA_DIR=$TARGET_DIR/data
LOG_DIR=$TARGET_DIR/logs
TARGET_KEYBOX=$TARGET_DIR/keybox.xml
TARGET_INJECTOR_CONFIG=$TARGET_DIR/injector.toml
STATE_DIR=/data/adb/omk
SECURITY_PATCH_PROP=$DATA_DIR/security_patch.prop
MODULE_SYSTEM_PROP=$MODDIR/system.prop
# A regular `system.prop` copy is only a fallback for module filesystems that
# reject symlinks.  Keep an in-file marker so a similarly shaped file owned by
# another module is never removed during restore.
SECURITY_PATCH_ENTRY_MARKER='# oh_my_keymint: managed security patch'

log_security_patch_entry() {
  SECURITY_PATCH_ENTRY_MESSAGE=$1
  echo "[oh_my_keymint] $SECURITY_PATCH_ENTRY_MESSAGE" >&2
  if [ -x /system/bin/log ]; then
    /system/bin/log -t oh_my_keymint "$SECURITY_PATCH_ENTRY_MESSAGE" 2>/dev/null || true
  fi
}

is_security_patch_date_token() {
  case "$1" in
    ????-??-??) ;;
    *) return 1 ;;
  esac
  SECURITY_PATCH_REST=${1#????-}
  SECURITY_PATCH_MONTH=${SECURITY_PATCH_REST%%-*}
  SECURITY_PATCH_DAY=${SECURITY_PATCH_REST#*-}
  case "$SECURITY_PATCH_MONTH" in
    01|02|03|04|05|06|07|08|09|10|11|12) ;;
    *) return 1 ;;
  esac
  case "$SECURITY_PATCH_DAY" in
    01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31) ;;
    *) return 1 ;;
  esac
}

is_managed_security_patch_entry() {
  [ -L "$MODULE_SYSTEM_PROP" ] && \
    [ "$(readlink "$MODULE_SYSTEM_PROP" 2>/dev/null)" = "$SECURITY_PATCH_PROP" ] && return 0
  [ -f "$MODULE_SYSTEM_PROP" ] || return 1
  SECURITY_PATCH_ENTRY_SIZE=$(wc -c < "$MODULE_SYSTEM_PROP" 2>/dev/null)
  [ -n "$SECURITY_PATCH_ENTRY_SIZE" ] && [ "$SECURITY_PATCH_ENTRY_SIZE" -le 256 ] || return 1
  SECURITY_PATCH_ENTRY_LINE1=$(sed -n '1p' "$MODULE_SYSTEM_PROP" 2>/dev/null)
  SECURITY_PATCH_ENTRY_LINE2=$(sed -n '2p' "$MODULE_SYSTEM_PROP" 2>/dev/null)
  SECURITY_PATCH_ENTRY_LINE3=$(sed -n '3p' "$MODULE_SYSTEM_PROP" 2>/dev/null)
  SECURITY_PATCH_ENTRY_LINE4=$(sed -n '4p' "$MODULE_SYSTEM_PROP" 2>/dev/null)
  if [ "$SECURITY_PATCH_ENTRY_LINE1" = "$SECURITY_PATCH_ENTRY_MARKER" ]; then
    [ -z "$SECURITY_PATCH_ENTRY_LINE4" ] || return 1
    SECURITY_PATCH_ENTRY_LINE1=$SECURITY_PATCH_ENTRY_LINE2
    SECURITY_PATCH_ENTRY_LINE2=$SECURITY_PATCH_ENTRY_LINE3
    SECURITY_PATCH_ENTRY_LINE3=
  else
    [ -z "$SECURITY_PATCH_ENTRY_LINE3" ] || return 1
  fi
  SECURITY_PATCH_SYSTEM_VALUE=
  SECURITY_PATCH_VENDOR_VALUE=
  SECURITY_PATCH_SYSTEM_LINE=
  SECURITY_PATCH_VENDOR_LINE=
  case "$SECURITY_PATCH_ENTRY_LINE1" in
    ro.vendor.build.security_patch=*)
      SECURITY_PATCH_VENDOR_VALUE=${SECURITY_PATCH_ENTRY_LINE1#*=}
      SECURITY_PATCH_SYSTEM_LINE=$SECURITY_PATCH_ENTRY_LINE2
      ;;
    ro.build.version.security_patch=*)
      SECURITY_PATCH_SYSTEM_VALUE=${SECURITY_PATCH_ENTRY_LINE1#*=}
      SECURITY_PATCH_VENDOR_LINE=$SECURITY_PATCH_ENTRY_LINE2
      ;;
    *) return 1 ;;
  esac
  case "$SECURITY_PATCH_SYSTEM_LINE" in
    ro.build.version.security_patch=*) SECURITY_PATCH_SYSTEM_VALUE=${SECURITY_PATCH_SYSTEM_LINE#*=} ;;
    *) ;;
  esac
  case "$SECURITY_PATCH_VENDOR_LINE" in
    ro.vendor.build.security_patch=*) SECURITY_PATCH_VENDOR_VALUE=${SECURITY_PATCH_VENDOR_LINE#*=} ;;
    *) ;;
  esac
  [ -n "$SECURITY_PATCH_SYSTEM_VALUE" ] && [ -n "$SECURITY_PATCH_VENDOR_VALUE" ] || return 1
  is_security_patch_date_token "$SECURITY_PATCH_SYSTEM_VALUE" || return 1
  is_security_patch_date_token "$SECURITY_PATCH_VENDOR_VALUE" || return 1
}

remove_managed_security_patch_entry() {
  if is_managed_security_patch_entry; then
    rm -f "$MODULE_SYSTEM_PROP" 2>/dev/null || \
      log_security_patch_entry "unable to remove stale managed system.prop"
  fi
}

ensure_security_patch_entry() {
  if [ ! -e "$SECURITY_PATCH_PROP" ]; then
    remove_managed_security_patch_entry
    return 0
  fi
  if [ ! -r "$SECURITY_PATCH_PROP" ]; then
    # The data mount or SELinux policy can briefly deny access even though the
    # durable file is present. Do not remove a valid module entry in that
    # window; a later late-load/post-mount pass can reconcile it safely.
    log_security_patch_entry "security-patch override exists but is not readable yet"
    return 0
  fi
  if is_managed_security_patch_entry; then
    # A symlink keeps the property loader pointed at the durable value and is
    # safe to retain across boots.  Only regular fallback copies need a
    # refresh, otherwise a manager that reads system.prop before this hook can
    # observe the previous synchronized date.
    if [ -L "$MODULE_SYSTEM_PROP" ]; then
      return 0
    fi
  elif [ -e "$MODULE_SYSTEM_PROP" ] || [ -L "$MODULE_SYSTEM_PROP" ]; then
    log_security_patch_entry "leaving non-OMK system.prop untouched"
    return 0
  fi

  SECURITY_PATCH_ENTRY_TMP="$MODDIR/.system.prop.omk-$$"
  rm -f "$SECURITY_PATCH_ENTRY_TMP" 2>/dev/null || true
  if ln -s "$SECURITY_PATCH_PROP" "$SECURITY_PATCH_ENTRY_TMP" 2>/dev/null \
    && mv -f "$SECURITY_PATCH_ENTRY_TMP" "$MODULE_SYSTEM_PROP" 2>/dev/null; then
    return 0
  fi
  rm -f "$SECURITY_PATCH_ENTRY_TMP" 2>/dev/null || true

  # A few module filesystems reject symlinks.  Also use this path to refresh a
  # managed regular copy (or to avoid a keystore_data_file symlink at the end
  # of post-fs-data). Never replace a non-OMK file that appeared during the
  # attempt.
  if [ -e "$MODULE_SYSTEM_PROP" ] || [ -L "$MODULE_SYSTEM_PROP" ]; then
    if ! is_managed_security_patch_entry; then
      log_security_patch_entry "system.prop symlink unavailable; leaving existing entry untouched"
      return 0
    fi
  fi
  if {
    printf '%s\n' "$SECURITY_PATCH_ENTRY_MARKER"
    cat "$SECURITY_PATCH_PROP"
  } > "$SECURITY_PATCH_ENTRY_TMP" 2>/dev/null \
    && chmod 0644 "$SECURITY_PATCH_ENTRY_TMP" 2>/dev/null \
    && mv -f "$SECURITY_PATCH_ENTRY_TMP" "$MODULE_SYSTEM_PROP" 2>/dev/null; then
    return 0
  fi
  rm -f "$SECURITY_PATCH_ENTRY_TMP" 2>/dev/null || true
  log_security_patch_entry "unable to install dynamic system.prop entry"
  return 0
}

# KernelSU's late-load hook reuses this script after the native early replay.
# Keep the mode side-effect free so it only reconciles the module-local
# system.prop entry and does not repeat post-fs-data initialization.
if [ "${1:-}" = "--reconcile-security-patch" ]; then
  ensure_security_patch_entry
  exit 0
fi

mkdir -p "$TARGET_DIR"
chmod 0770 "$TARGET_DIR"
chown 1017:1017 "$TARGET_DIR"

mkdir -p "$DATA_DIR"
chmod 0770 "$DATA_DIR"
chown 1017:1017 "$DATA_DIR"

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

# This must run before Zygote/framework startup so their cached security-patch
# values are initialized from the synchronized properties.  Keep the helper as
# a separate asset so the same bounded invocation can be reused by KernelSU's
# post-mount and late-load stages.
EARLY_HELPER="$MODDIR/early-security-patch.sh"
if [ -f "$EARLY_HELPER" ]; then
  # Invoke through the platform shell: some root implementations leave
  # module files with a non-executable SELinux label during post-fs-data.
  /system/bin/sh "$EARLY_HELPER" post-fs-data
else
  echo "[oh_my_keymint] post-fs-data: early-security-patch helper is missing" >&2
fi

# The native helper may have rebuilt or removed the durable file from config;
# reconcile the module-local boot entry after that decision.  This also cleans
# a dangling entry when the user selected Restore default security patch.
ensure_security_patch_entry

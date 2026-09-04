#!/system/bin/sh

# This helper is intentionally a short-lived shell wrapper.  It is called from
# post-fs-data (and, on KernelSU, post-mount/late-load) so the native binary can
# update the property area before framework processes cache Build.VERSION.

MODDIR=${0%/*}
EARLY_STAGE=${1:-unknown}
STATE_DIR=/data/adb/omk
CONFIG_PATH=/data/misc/keystore/omk/config.toml
SNAPSHOT_PATH=/data/misc/keystore/omk/data/security_patch_defaults.toml
SYSTEM_SECURITY_PATCH_PROPERTY=ro.build.version.security_patch
VENDOR_SECURITY_PATCH_PROPERTY=ro.vendor.build.security_patch

# Starting a statically linked Rust process can take noticeably longer on
# slower UFS/eMMC devices while /data and the linker namespaces are coming up.
# Keep each invocation bounded, but give it enough time to finish before the
# framework starts caching Build.VERSION.SECURITY_PATCH.
case "$EARLY_STAGE" in
  post-fs-data)
    # KernelSU and Magisk run this hook on the critical pre-zygote path. Keep
    # the fallback bounded to roughly four seconds: one shell replay and one
    # matching-ABI native invocation.
    EARLY_TIMEOUT_SECONDS=2
    EARLY_ATTEMPTS=1
    EARLY_SHELL_ATTEMPTS=1
    EARLY_NATIVE_CANDIDATES=1
    ;;
  post-mount)
    EARLY_TIMEOUT_SECONDS=4
    EARLY_ATTEMPTS=1
    EARLY_SHELL_ATTEMPTS=4
    EARLY_NATIVE_CANDIDATES=2
    ;;
  late-load)
    EARLY_TIMEOUT_SECONDS=4
    EARLY_ATTEMPTS=1
    EARLY_SHELL_ATTEMPTS=2
    EARLY_NATIVE_CANDIDATES=2
    ;;
  *)
    EARLY_TIMEOUT_SECONDS=2
    EARLY_ATTEMPTS=1
    EARLY_SHELL_ATTEMPTS=1
    EARLY_NATIVE_CANDIDATES=1
    ;;
esac

early_log() {
  EARLY_MESSAGE=$1
  echo "[oh_my_keymint] $EARLY_MESSAGE" >&2
  if [ -x /system/bin/log ]; then
    /system/bin/log -t oh_my_keymint "$EARLY_MESSAGE" 2>/dev/null || true
  elif command -v log >/dev/null 2>&1; then
    log -t oh_my_keymint "$EARLY_MESSAGE" 2>/dev/null || true
  fi
}

# The native daemon is deliberately kept as a fallback.  On some devices the
# post-fs-data linker namespace is not ready yet, while the root implementation
# already exposes resetprop.  Reading the small, validated trust section here
# lets us replay the persisted WebUI override without starting the full daemon.
is_early_patch_date() {
  case "$1" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) return 1 ;;
  esac

  EARLY_PATCH_REST=${1#????-}
  EARLY_PATCH_MONTH=${EARLY_PATCH_REST%%-*}
  EARLY_PATCH_DAY=${EARLY_PATCH_REST#*-}
  case "$EARLY_PATCH_MONTH" in
    01|02|03|04|05|06|07|08|09|10|11|12) ;;
    *) return 1 ;;
  esac
  case "$EARLY_PATCH_DAY" in
    01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31) ;;
    *) return 1 ;;
  esac
}

read_early_trust_patch() {
  [ -r "$CONFIG_PATH" ] || return 1

  # config.toml is written by the Rust TOML serializer.  Only read quoted
  # scalar assignments inside [trust]; ignore comments and every other table.
  EARLY_PATCH_FIELDS=$(awk '
    BEGIN { in_trust = 0; security = ""; os = ""; vendor = ""; boot = "" }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      in_trust = ($0 ~ /^[[:space:]]*\[trust\][[:space:]]*$/)
      next
    }
    in_trust && $0 ~ /^[[:space:]]*(security_patch|os_patchlevel|vendor_patchlevel|boot_patchlevel)[[:space:]]*=/ {
      line = $0
      key = line
      sub(/[[:space:]]*=.*/, "", key)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
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
        printf "%s\t%s\t%s\t%s\n", security, os, vendor, boot
    }
  ' "$CONFIG_PATH" 2>/dev/null)
  [ -n "$EARLY_PATCH_FIELDS" ] || return 1

  # Convert the tab separators to spaces before field splitting.  Patch values
  # are date/auto tokens, so they cannot contain whitespace.
  EARLY_PATCH_FIELDS=$(printf '%s\n' "$EARLY_PATCH_FIELDS" | tr '\t' ' ')
  set -- $EARLY_PATCH_FIELDS
  [ "$#" -eq 4 ] || return 1
  [ "$1" = "$2" ] && [ "$1" = "$3" ] && [ "$1" = "$4" ] || return 1
  is_early_patch_date "$1" || return 1
  EARLY_PATCH_DATE=$1
}

has_early_snapshot() {
  [ -f "$SNAPSHOT_PATH" ] || return 1
  # The Rust path performs the complete TOML/fingerprint/date validation.  The
  # shell guard only needs the durable version marker to distinguish a WebUI
  # synchronization from a manually authored exact-date config.
  grep -F 'version = 1' "$SNAPSHOT_PATH" >/dev/null 2>&1
}

early_resetprop_get() {
  if [ "$EARLY_RESETPROP_MODE" = multi ]; then
    "$EARLY_RESETPROP_BIN" resetprop "$1" 2>/dev/null
  else
    "$EARLY_RESETPROP_BIN" "$1" 2>/dev/null
  fi
}

early_resetprop_set() {
  if [ "$EARLY_RESETPROP_MODE" = multi ]; then
    "$EARLY_RESETPROP_BIN" resetprop -n "$1" "$2" >/dev/null 2>&1
  else
    "$EARLY_RESETPROP_BIN" -n "$1" "$2" >/dev/null 2>&1
  fi
}

early_resetprop_matches_target() {
  EARLY_VENDOR_VALUE=$(early_resetprop_get "$VENDOR_SECURITY_PATCH_PROPERTY")
  EARLY_SYSTEM_VALUE=$(early_resetprop_get "$SYSTEM_SECURITY_PATCH_PROPERTY")
  [ "$EARLY_VENDOR_VALUE" = "$EARLY_PATCH_DATE" ] \
    && [ "$EARLY_SYSTEM_VALUE" = "$EARLY_PATCH_DATE" ]
}

replay_security_patch_with_shell_candidate() {
  EARLY_RESETPROP_BIN=$1
  EARLY_RESETPROP_MODE=direct
  case "$EARLY_RESETPROP_BIN" in
    */ksud|*/apd) EARLY_RESETPROP_MODE=multi ;;
  esac

  EARLY_SHELL_ATTEMPT=1
  while [ "$EARLY_SHELL_ATTEMPT" -le "$EARLY_SHELL_ATTEMPTS" ]; do
    # Read first and only update properties that still differ.  A previous
    # candidate may have successfully changed one side before failing on the
    # other; repeating that write is unnecessary and can race init again.
    EARLY_VENDOR_VALUE=$(early_resetprop_get "$VENDOR_SECURITY_PATCH_PROPERTY")
    EARLY_SYSTEM_VALUE=$(early_resetprop_get "$SYSTEM_SECURITY_PATCH_PROPERTY")
    if [ "$EARLY_VENDOR_VALUE" = "$EARLY_PATCH_DATE" ] \
      && [ "$EARLY_SYSTEM_VALUE" = "$EARLY_PATCH_DATE" ]; then
      early_log "${EARLY_STAGE}: replayed security patch $EARLY_PATCH_DATE before framework startup"
      return 0
    fi

    EARLY_WRITE_FAILED=0
    if [ "$EARLY_VENDOR_VALUE" != "$EARLY_PATCH_DATE" ]; then
      if ! early_resetprop_set "$VENDOR_SECURITY_PATCH_PROPERTY" "$EARLY_PATCH_DATE"; then
        EARLY_WRITE_FAILED=1
      fi
    fi
    if [ "$EARLY_SYSTEM_VALUE" != "$EARLY_PATCH_DATE" ]; then
      if ! early_resetprop_set "$SYSTEM_SECURITY_PATCH_PROPERTY" "$EARLY_PATCH_DATE"; then
        EARLY_WRITE_FAILED=1
      fi
    fi

    # Verify even after a reported write failure.  Some resetprop wrappers
    # return a non-zero status after committing the mmap update; accepting a
    # fully verified pair avoids needlessly invoking another writer.
    if early_resetprop_matches_target; then
      early_log "${EARLY_STAGE}: replayed security patch $EARLY_PATCH_DATE before framework startup"
      return 0
    fi
    # A candidate that cannot update the pair is abandoned immediately.  The
    # next candidate sees the current values and writes only the missing side.
    if [ "$EARLY_WRITE_FAILED" -ne 0 ]; then
      return 1
    fi
    if [ "$EARLY_SHELL_ATTEMPT" -lt "$EARLY_SHELL_ATTEMPTS" ]; then
      sleep 0.2
    fi
    EARLY_SHELL_ATTEMPT=$((EARLY_SHELL_ATTEMPT + 1))
  done
  return 1
}

replay_security_patch_with_shell() {
  has_early_snapshot || return 1
  read_early_trust_patch || return 1

  # Keep the order aligned with the native resetprop resolver.  A command may
  # be executable yet incompatible, so each candidate gets its own bounded
  # replay attempt instead of allowing the first path to mask the others.
  EARLY_PATH_CANDIDATE=$(command -v resetprop 2>/dev/null)
  EARLY_SEEN_CANDIDATES='|'
  for EARLY_PATH in \
    /data/adb/ksu/bin/resetprop \
    /data/adb/magisk/resetprop \
    /data/adb/ap/bin/resetprop \
    /data/adb/ksud \
    /data/adb/apd \
    "$EARLY_PATH_CANDIDATE" \
    /system_ext/bin/resetprop \
    /system/bin/resetprop
  do
    [ -n "$EARLY_PATH" ] && [ -x "$EARLY_PATH" ] || continue
    case "$EARLY_PATH" in
      *'|'*)
        early_log "${EARLY_STAGE}: ignoring resetprop path with separator"
        continue
        ;;
    esac
    case "$EARLY_SEEN_CANDIDATES" in
      *"|$EARLY_PATH|"*) continue ;;
    esac
    EARLY_SEEN_CANDIDATES="${EARLY_SEEN_CANDIDATES}${EARLY_PATH}|"
    if replay_security_patch_with_shell_candidate "$EARLY_PATH"; then
      return 0
    fi
  done
  return 1
}

normalize_early_abi() {
  case "$1" in
    arm64-v8a|aarch64|arm64)
      printf '%s\n' arm64-v8a
      ;;
    x86_64|amd64|x64)
      printf '%s\n' x86_64
      ;;
  esac
}

detect_early_abi() {
  EARLY_ABI_VALUE=
  if [ -x /system/bin/getprop ]; then
    EARLY_ABI_VALUE=$(/system/bin/getprop ro.product.cpu.abilist 2>/dev/null)
  elif command -v getprop >/dev/null 2>&1; then
    EARLY_ABI_VALUE=$(getprop ro.product.cpu.abilist 2>/dev/null)
  fi

  for EARLY_ABI_TOKEN in $(printf '%s' "$EARLY_ABI_VALUE" | tr ',' ' '); do
    EARLY_ABI_NORMALIZED=$(normalize_early_abi "$EARLY_ABI_TOKEN")
    if [ -n "$EARLY_ABI_NORMALIZED" ]; then
      printf '%s\n' "$EARLY_ABI_NORMALIZED"
      return 0
    fi
  done

  if [ -x /system/bin/getprop ]; then
    EARLY_ABI_VALUE=$(/system/bin/getprop ro.product.cpu.abi 2>/dev/null)
  elif command -v getprop >/dev/null 2>&1; then
    EARLY_ABI_VALUE=$(getprop ro.product.cpu.abi 2>/dev/null)
  fi
  EARLY_ABI_NORMALIZED=$(normalize_early_abi "$EARLY_ABI_VALUE")
  if [ -n "$EARLY_ABI_NORMALIZED" ]; then
    printf '%s\n' "$EARLY_ABI_NORMALIZED"
    return 0
  fi

  EARLY_ABI_NORMALIZED=$(normalize_early_abi "${ARCH:-}")
  if [ -n "$EARLY_ABI_NORMALIZED" ]; then
    printf '%s\n' "$EARLY_ABI_NORMALIZED"
    return 0
  fi

  EARLY_ABI_NORMALIZED=$(normalize_early_abi "$(uname -m 2>/dev/null)")
  [ -n "$EARLY_ABI_NORMALIZED" ] && printf '%s\n' "$EARLY_ABI_NORMALIZED"
}

select_early_candidate() {
  EARLY_PATH=$1
  [ -f "$EARLY_PATH" ] || return 1
  return 0
}

run_early_candidate() {
  EARLY_KEYMINT=$1
  if ! select_early_candidate "$EARLY_KEYMINT"; then
    return 1
  fi

  chmod 0755 "$EARLY_KEYMINT" 2>/dev/null || true
  chcon u:object_r:system_file:s0 "$EARLY_KEYMINT" 2>/dev/null || true
  if [ ! -x "$EARLY_KEYMINT" ]; then
    early_log "${EARLY_STAGE}: candidate is not executable: $EARLY_KEYMINT"
    return 1
  fi

  EARLY_ATTEMPT=1
  while [ "$EARLY_ATTEMPT" -le "$EARLY_ATTEMPTS" ]; do
    EARLY_OUTPUT=$(run_early_keymint_once 2>&1)
    EARLY_STATUS=$?
    if [ "$EARLY_STATUS" -eq 0 ]; then
      return 0
    fi
    if [ -n "$EARLY_OUTPUT" ]; then
      early_log "${EARLY_STAGE}: $EARLY_OUTPUT"
    fi
    early_log "${EARLY_STAGE}: early replay attempt $EARLY_ATTEMPT failed for $EARLY_KEYMINT (status $EARLY_STATUS)"
    # Exec-format and missing-interpreter failures cannot be repaired by
    # retrying the same file; immediately try the next ABI/copy instead.
    if [ "$EARLY_STATUS" -eq 126 ] || [ "$EARLY_STATUS" -eq 127 ]; then
      break
    fi
    if [ "$EARLY_ATTEMPT" -lt "$EARLY_ATTEMPTS" ]; then
      sleep 1
    fi
    EARLY_ATTEMPT=$((EARLY_ATTEMPT + 1))
  done
  return 1
}

reapply_security_patch_early() {
  EARLY_ABI=$(detect_early_abi)

  # The post-fs-data budget deliberately permits only the matching packaged
  # ABI. Later hooks may try the hot-update copy and a second packaged ABI.
  # Run the native path first: unlike the shell-only fallback it also repairs
  # and persists security_patch.prop, which is consumed by system.prop on the
  # next boot.
  if [ "$EARLY_NATIVE_CANDIDATES" -eq 1 ]; then
    if [ -n "$EARLY_ABI" ] \
      && run_early_candidate "$MODDIR/libs/$EARLY_ABI/keymint"; then
      return 0
    fi
    early_log "${EARLY_STAGE}: matching-ABI native replay did not complete"
  else
    # Try the hot-update and module-root copies first so the early path follows
    # the same binary selection as the normal daemon. If either is stale or has
    # the wrong architecture, continue with the ABI-specific packaged binary.
    EARLY_NATIVE_TRIED=0
    for EARLY_PATH in \
      "$STATE_DIR/keymint" \
      "$MODDIR/keymint"
    do
      [ "$EARLY_NATIVE_TRIED" -lt "$EARLY_NATIVE_CANDIDATES" ] || break
      # Do not consume the finite candidate budget for paths that are not part
      # of this installation. This lets a later hook still try the packaged
      # ABI when no hot-update copy exists.
      [ -f "$EARLY_PATH" ] || continue
      EARLY_NATIVE_TRIED=$((EARLY_NATIVE_TRIED + 1))
      if run_early_candidate "$EARLY_PATH"; then
        return 0
      fi
    done

    if [ "$EARLY_NATIVE_TRIED" -lt "$EARLY_NATIVE_CANDIDATES" ] \
      && [ -n "$EARLY_ABI" ] \
      && [ -f "$MODDIR/libs/$EARLY_ABI/keymint" ]; then
      EARLY_NATIVE_TRIED=$((EARLY_NATIVE_TRIED + 1))
      if run_early_candidate "$MODDIR/libs/$EARLY_ABI/keymint"; then
        return 0
      fi
    fi

    # If ABI properties were unavailable, or the reported ABI did not match the
    # packaged payload, try each remaining architecture. A failed exec simply
    # falls through to the next candidate; no arbitrary candidate is selected
    # without an execution attempt.
    for EARLY_PATH in \
      "$MODDIR/libs/arm64-v8a/keymint" \
      "$MODDIR/libs/x86_64/keymint"
    do
      [ "$EARLY_NATIVE_TRIED" -lt "$EARLY_NATIVE_CANDIDATES" ] || break
      if [ "$EARLY_PATH" = "$MODDIR/libs/$EARLY_ABI/keymint" ]; then
        continue
      fi
      [ -f "$EARLY_PATH" ] || continue
      EARLY_NATIVE_TRIED=$((EARLY_NATIVE_TRIED + 1))
      if run_early_candidate "$EARLY_PATH"; then
        return 0
      fi
    done
  fi

  # A device may expose resetprop before the application linker namespace can
  # start the Rust binary. Keep that shell path as a bounded fallback; it
  # still fixes the live property area for the current boot.
  if replay_security_patch_with_shell; then
    return 0
  fi

  early_log "${EARLY_STAGE}: no candidate completed early security-patch replay"
  return 0
}

run_early_keymint_once() {
  EARLY_TIMEOUT_BIN=$(command -v timeout 2>/dev/null)
  if [ -n "$EARLY_TIMEOUT_BIN" ] && [ -x "$EARLY_TIMEOUT_BIN" ]; then
    "$EARLY_TIMEOUT_BIN" "$EARLY_TIMEOUT_SECONDS" "$EARLY_KEYMINT" --early-security-patch
    return $?
  fi

  # Magisk and KernelSU normally provide timeout through BusyBox.  Keep a
  # bounded POSIX fallback for stripped-down root environments.  A separate
  # watchdog avoids polling kill -0, which can report true for a zombie child
  # until the parent calls wait(2).
  "$EARLY_KEYMINT" --early-security-patch &
  EARLY_PID=$!
  (
    sleep "$EARLY_TIMEOUT_SECONDS"
    if kill -0 "$EARLY_PID" 2>/dev/null; then
      kill -TERM "$EARLY_PID" 2>/dev/null || true
      sleep 1
      kill -KILL "$EARLY_PID" 2>/dev/null || true
    fi
  ) &
  EARLY_WATCHDOG=$!
  wait "$EARLY_PID"
  EARLY_STATUS=$?
  kill "$EARLY_WATCHDOG" 2>/dev/null || true
  wait "$EARLY_WATCHDOG" 2>/dev/null || true
  return "$EARLY_STATUS"
}

reapply_security_patch_early

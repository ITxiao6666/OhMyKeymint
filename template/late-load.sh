#!/system/bin/sh

MODDIR=${0%/*}
EARLY_HELPER="$MODDIR/early-security-patch.sh"

# KernelSU late-load has no post-fs-data phase.  This is necessarily a
# best-effort replay because framework processes may already have cached the
# original value, but it keeps the property correct for subsequently started
# processes and for the next supported boot path.
if [ -f "$EARLY_HELPER" ]; then
  /system/bin/sh "$EARLY_HELPER" late-load
fi

# The early helper may create, refresh, or remove the durable override after
# reading config.toml. Reconcile the module entry before KernelSU loads
# system.prop so a restore cannot leave a stale regular copy behind.
RECONCILE_SCRIPT="$MODDIR/post-fs-data.sh"
if [ -f "$RECONCILE_SCRIPT" ]; then
  /system/bin/sh "$RECONCILE_SCRIPT" --reconcile-security-patch
fi

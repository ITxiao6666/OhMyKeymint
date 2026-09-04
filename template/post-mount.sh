#!/system/bin/sh

MODDIR=${0%/*}
EARLY_HELPER="$MODDIR/early-security-patch.sh"

# KernelSU runs this after system.prop and module mounts.  Replaying here
# covers ROMs that populate the read-only properties later than post-fs-data;
# Magisk simply ignores this optional hook.
if [ -f "$EARLY_HELPER" ]; then
  /system/bin/sh "$EARLY_HELPER" post-mount
fi

MODDIR=${0%/*}
cd $MODDIR

# Fork-based supervisor for instant restart
./supervisor ./daemon "$MODDIR" &

# Debug builds ship diag.sh; its presence enables the external-storage diagnostic plane.
if [ -f "$MODDIR/diag.sh" ]; then
  . "$MODDIR/diag.sh"
  diag_setup
fi

# Clear logd size persist properties once boot completes
# (
#   until [ "$(getprop sys.boot_completed)" = "1" ]; do
#     sleep 1
#   done
#   setprop persist.logd.size ""
#   setprop persist.logd.size.crash ""
#   setprop persist.logd.size.system ""
#   setprop persist.logd.size.main ""
# ) &

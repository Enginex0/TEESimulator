MODDIR=${0%/*}
cd $MODDIR

# Fork-based supervisor for instant restart
./supervisor ./daemon "$MODDIR" &

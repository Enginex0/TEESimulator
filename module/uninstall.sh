#!/system/bin/sh
MODDIR=${0%/*}
CONFIG_DIR=/data/adb/tricky_store

# Kill daemon and supervisor
for pid in $(pidof TEESimulator) $(pidof supervisor) $(pidof daemon); do
    kill -9 "$pid" 2>/dev/null
done

rm -rf "$CONFIG_DIR/persistent_keys"
rm -f "$CONFIG_DIR/tee_status.txt"

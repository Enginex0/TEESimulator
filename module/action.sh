#!/system/bin/sh
MODDIR=${0%/*}
CONFIG_DIR=/data/adb/tricky_store

if [ -d "$CONFIG_DIR/persistent_keys" ]; then
    rm -rf "$CONFIG_DIR/persistent_keys"
    mkdir -p "$CONFIG_DIR/persistent_keys"
    echo "Persistent key storage cleared"
else
    echo "No persistent key storage found"
fi

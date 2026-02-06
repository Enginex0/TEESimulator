#!/system/bin/sh
MODDIR=${0%/*}
CONFIG_DIR=/data/adb/tricky_store

echo "============================================"
echo "  TEESimulator — Key Storage Maintenance"
echo "============================================"
echo ""

if [ -d "$CONFIG_DIR/persistent_keys" ]; then
    KEY_COUNT=$(find "$CONFIG_DIR/persistent_keys" -name "*.bin" 2>/dev/null | wc -l)
    STORAGE_SIZE=$(du -sh "$CONFIG_DIR/persistent_keys" 2>/dev/null | cut -f1)

    echo "  Cached keys found : $KEY_COUNT"
    echo "  Storage used      : $STORAGE_SIZE"
    echo ""

    rm -rf "$CONFIG_DIR/persistent_keys"
    mkdir -p "$CONFIG_DIR/persistent_keys"

    echo "  [OK] All cached attestation keys purged"
    echo "  [OK] Fresh keys will generate on next request"
else
    echo "  No persistent key storage found"
    echo "  Nothing to clear"
fi

echo ""
echo "============================================"

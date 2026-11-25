#!/bin/bash
# '/etc/init.d/pbr dnsprefetch' must run pbr.user.dnsprefetch in standalone
# mode, pass its exit status back, and leave ucode and the caller's
# environment alone.
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

cat << EOF > "$TEST_DIR/mock_ucode"
#!/bin/bash
echo "\$1" >> "$TEST_DIR/ucode_calls"
exit 0
EOF
chmod +x "$TEST_DIR/mock_ucode"

cat << EOF > "$TEST_DIR/pbr.user.dnsprefetch"
echo "\${PBR_DNSPREFETCH_MODE:-unset}" >> "$TEST_DIR/prefetch_runs"
exit "\${MOCK_PREFETCH_RC:-0}"
EOF

mkdir -p "$TEST_DIR/var_run"
touch "$TEST_DIR/ucode_calls"

cp files/etc/init.d/pbr "$TEST_DIR/pbr_mock.sh"
sed -i "s|/var/run|$TEST_DIR/var_run|g" "$TEST_DIR/pbr_mock.sh"
sed -i "s|/usr/share/\${packageName}/pbr.user.dnsprefetch|$TEST_DIR/pbr.user.dnsprefetch|g" "$TEST_DIR/pbr_mock.sh"
sed -i "s|readonly _ucode=.*|readonly _ucode=\"$TEST_DIR/mock_ucode\"|g" "$TEST_DIR/pbr_mock.sh"
sed -i 's|^\. /lib/functions.sh|# . /lib/functions.sh|' "$TEST_DIR/pbr_mock.sh"
sed -i 's|^\. /lib/functions/network.sh|# . /lib/functions/network.sh|' "$TEST_DIR/pbr_mock.sh"
sed -i 's|^\. "${IPKG_INSTROOT}/usr/share/libubox/jshn.sh"|# . /usr/share/libubox/jshn.sh|' "$TEST_DIR/pbr_mock.sh"

(
    unset PBR_DNSPREFETCH_MODE

    . "$TEST_DIR/pbr_mock.sh"

    case " $EXTRA_COMMANDS " in
        *' dnsprefetch '*) ;;
        *)
            echo "FAIL: dnsprefetch missing from EXTRA_COMMANDS: $EXTRA_COMMANDS" > "$TEST_DIR/result"
            exit 1
            ;;
    esac

    # Test 1: runs the file in standalone mode and returns its status
    if ! dnsprefetch; then
        echo "FAIL: dnsprefetch failed although the script returned 0!" > "$TEST_DIR/result"
        exit 1
    fi
    if [ "$(cat "$TEST_DIR/prefetch_runs" 2>/dev/null)" != "standalone" ]; then
        echo "FAIL: script not run once in standalone mode: $(cat "$TEST_DIR/prefetch_runs" 2>/dev/null)" > "$TEST_DIR/result"
        exit 1
    fi

    # Test 2: a failing run is reported to the caller (cron mails it)
    MOCK_PREFETCH_RC=3 dnsprefetch
    rc=$?
    if [ "$rc" -ne 3 ]; then
        echo "FAIL: exit status 3 of the script came back as $rc!" > "$TEST_DIR/result"
        exit 1
    fi

    # Test 3: nothing leaks into ucode or into the caller's environment
    if [ -s "$TEST_DIR/ucode_calls" ]; then
        echo "FAIL: ucode was called: $(cat "$TEST_DIR/ucode_calls")" > "$TEST_DIR/result"
        exit 1
    fi
    if [ -n "${PBR_DNSPREFETCH_MODE+set}" ]; then
        echo "FAIL: PBR_DNSPREFETCH_MODE leaked into the caller's shell!" > "$TEST_DIR/result"
        exit 1
    fi

    echo "PASS" > "$TEST_DIR/result"
) >/dev/null 2>&1

if [ "$(cat "$TEST_DIR/result")" = "PASS" ]; then
    exit 0
else
    cat "$TEST_DIR/result" >&2
    exit 1
fi

#!/bin/bash
# Raw curl examples for the RustChain Attestation Bridge.
# Run after starting the bridge:  npm start
#
# Usage:
#   ./examples/client-curl.sh
#   ./examples/client-curl.sh https://attest.elyanlabs.io   # against deployed bridge

BRIDGE_URL="${1:-http://localhost:3001}"

echo "═══ Health check ═══"
curl -s "${BRIDGE_URL}/health" | python3 -m json.tool
echo ""

echo "═══ Bridge public key (for offline verification) ═══"
curl -s "${BRIDGE_URL}/pubkey" | python3 -m json.tool
echo ""

echo "═══ Submit fingerprint, get token ═══"
TOKEN=$(curl -s -X POST "${BRIDGE_URL}/attest" \
  -H "Content-Type: application/json" \
  -d '{
    "hardware_id": "curl-example-real-hw-aaaaaaaa",
    "device": {"device_family": "x86_64", "device_arch": "modern", "device_model": "Intel Xeon E5-2670"},
    "checks": {
      "anti_emulation": {"passed": true, "data": {}},
      "clock_drift": {"passed": true, "data": {"cv": 0.1}},
      "cache_timing": {"passed": true},
      "simd_identity": {"passed": true},
      "thermal_drift": {"passed": true},
      "instruction_jitter": {"passed": true}
    }
  }' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

echo "Token: ${TOKEN:0:60}..."
echo ""

echo "═══ Verify token ═══"
curl -s "${BRIDGE_URL}/verify/${TOKEN}" | python3 -m json.tool
echo ""

echo "═══ Reject VM-detected submission ═══"
curl -s -X POST "${BRIDGE_URL}/attest" \
  -H "Content-Type: application/json" \
  -d '{
    "hardware_id": "curl-example-vm-spoofed-bbbbbb",
    "device": {"device_family": "x86_64", "device_arch": "modern"},
    "checks": {
      "anti_emulation": {"passed": false, "data": {"vm_indicators": ["cpuinfo:hypervisor", "/sys/class/dmi/id/sys_vendor:qemu"]}}
    }
  }' | python3 -m json.tool

#!/bin/bash
set -e

echo "=== Deploy MoneroVM Challenge Contract to Starknet Sepolia ==="
echo ""

# Check if sncast is installed
if ! command -v sncast &> /dev/null; then
  echo "❌ sncast not found. Install with:"
  echo "  curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh"
  echo "  export PATH=\"\$HOME/.local/share/starknet-foundry/bin:\$PATH\""
  exit 1
fi

echo "✅ sncast found: $(sncast --version)"
echo ""

# RPC URL - Starknet Sepolia
RPC_URL="${STARKNET_RPC_URL:-https://starknet-sepolia.public.blastapi.io/rpc/v0_7}"
echo "📡 Using RPC: $RPC_URL"
echo ""

# Check for account
ACCOUNT_NAME="${STARKNET_ACCOUNT:-deployer}"
echo "👤 Using account: $ACCOUNT_NAME"
echo ""

# Navigate to monero-vm directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Build contract
echo "📦 Building MoneroVM contracts..."
scarb build

# Check if contract compiled
CONTRACT_CLASS="target/dev/monero_vm_ChallengeContract.contract_class.json"
if [ ! -f "$CONTRACT_CLASS" ]; then
  echo "❌ Contract build failed. Check for compilation errors."
  exit 1
fi

echo "✅ Contract compiled"
echo ""

# Declare contract
echo "📄 Declaring ChallengeContract..."

DECLARE_OUTPUT=$(sncast declare \
  --contract-name "ChallengeContract" \
  --url "$RPC_URL" 2>&1) || true

echo "$DECLARE_OUTPUT"

# Extract class hash
if echo "$DECLARE_OUTPUT" | grep -q "class_hash"; then
  CLASS_HASH=$(echo "$DECLARE_OUTPUT" | grep -oE 'class_hash: 0x[a-fA-F0-9]+' | grep -oE '0x[a-fA-F0-9]+' | head -1)
elif echo "$DECLARE_OUTPUT" | grep -qi "already declared"; then
  CLASS_HASH=$(echo "$DECLARE_OUTPUT" | grep -oE '0x[a-fA-F0-9]{64}' | head -1)
else
  echo "❌ Declaration failed"
  exit 1
fi

echo ""
echo "✅ Class Hash: $CLASS_HASH"
echo ""

# Deploy contract (no constructor args for ChallengeContract)
echo "🚀 Deploying contract instance..."

DEPLOY_OUTPUT=$(sncast deploy \
  --class-hash "$CLASS_HASH" \
  --url "$RPC_URL" 2>&1) || true

echo "$DEPLOY_OUTPUT"

# Extract contract address
if echo "$DEPLOY_OUTPUT" | grep -q "contract_address"; then
  CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep -oE 'contract_address: 0x[a-fA-F0-9]+' | grep -oE '0x[a-fA-F0-9]+' | head -1)
  echo ""
  echo "✅ CONTRACT DEPLOYED!"
  echo "   Address: $CONTRACT_ADDRESS"
  echo "   Network: Starknet Sepolia"
  echo ""
  echo "🔗 View on Starkscan:"
  echo "   https://sepolia.starkscan.co/contract/$CONTRACT_ADDRESS"
  echo ""
  echo "📝 Save this address for your announcement!"
else
  echo "❌ Deployment failed"
  exit 1
fi

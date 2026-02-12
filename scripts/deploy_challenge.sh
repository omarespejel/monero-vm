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
# Note: Blast API was discontinued. Default to Alchemy's free public demo endpoint.
# For production, set STARKNET_RPC_URL to your own Alchemy/Infura/Nethermind key.
RPC_URL="${STARKNET_RPC_URL:-https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_7/demo}"
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

# Deploy contract with owner constructor arg
# The owner address defaults to the deployer account address.
# Override with OWNER_ADDRESS env var if needed.
OWNER_ADDRESS="${OWNER_ADDRESS:-}"

if [ -z "$OWNER_ADDRESS" ]; then
  echo "ℹ️  No OWNER_ADDRESS set. Fetching deployer account address..."
  OWNER_ADDRESS=$(sncast account info --name "$ACCOUNT_NAME" --url "$RPC_URL" 2>&1 | grep -oE '0x[a-fA-F0-9]+' | head -1) || true
  if [ -z "$OWNER_ADDRESS" ]; then
    echo "❌ Could not determine owner address. Set OWNER_ADDRESS env var manually."
    echo "   Example: OWNER_ADDRESS=0xYOUR_ADDRESS ./scripts/deploy_challenge.sh"
    exit 1
  fi
fi

# Bond token: 0 = disabled (testnet). Set BOND_TOKEN_ADDRESS for mainnet ERC20.
BOND_TOKEN="${BOND_TOKEN_ADDRESS:-0}"
echo "🚀 Deploying contract instance..."
echo "   Owner: $OWNER_ADDRESS"
echo "   Bond token: $BOND_TOKEN (0 = disabled)"

DEPLOY_OUTPUT=$(sncast deploy \
  --class-hash "$CLASS_HASH" \
  --constructor-calldata "$OWNER_ADDRESS" "$BOND_TOKEN" \
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

#!/usr/bin/env bash
#
# Deploy the sealed TOPRF node image to Azure.
#
# Downloads the VHD from CI artifacts, uploads to Azure as a managed disk,
# creates a gallery image, and optionally launches CVMs.
#
# Prerequisites:
#   - az cli logged in
#   - azcopy installed
#   - VHD file (from CI build)
#
# Usage:
#   ./deploy-azure.sh --vhd toprf-node-sealed.vhd --region eastus --nodes 3
#
set -euo pipefail

VHD=""
REGION="eastus"
NUM_NODES=0
RG="toprf-cvm"
GALLERY="toprfGallery"
IMAGE_DEF="toprf-node-sealed"
VM_SIZE="Standard_DC2as_v5"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vhd)     VHD="$2"; shift 2 ;;
        --region)  REGION="$2"; shift 2 ;;
        --nodes)   NUM_NODES="$2"; shift 2 ;;
        --rg)      RG="$2"; shift 2 ;;
        *)
            echo "Usage: $0 --vhd <path> [--region <region>] [--nodes <count>] [--rg <name>]"
            exit 1
            ;;
    esac
done

if [[ -z "$VHD" || ! -f "$VHD" ]]; then
    echo "Error: --vhd <path> required (download from CI artifacts)"
    exit 1
fi

VHD_SIZE=$(stat -f%z "$VHD" 2>/dev/null || stat -c%s "$VHD")
echo "=== Deploying Sealed TOPRF Image to Azure ==="
echo "  VHD:    $VHD ($(( VHD_SIZE / 1024 / 1024 )) MB)"
echo "  Region: $REGION"
echo "  RG:     $RG"
echo ""

# ---- 1. Resource group ----
echo "[1/5] Creating resource group..."
az group create --name "$RG" --location "$REGION" -o none

# ---- 2. Upload VHD as managed disk ----
echo "[2/5] Uploading VHD..."
DISK_NAME="toprf-sealed-$(date +%Y%m%d%H%M%S)"

az disk create \
    --resource-group "$RG" \
    --name "$DISK_NAME" \
    --location "$REGION" \
    --upload-type Upload \
    --upload-size-bytes "$VHD_SIZE" \
    --os-type Linux \
    --hyper-v-generation V2 \
    --security-type ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey \
    --sku StandardSSD_LRS \
    -o none

SAS=$(az disk grant-access \
    --resource-group "$RG" \
    --name "$DISK_NAME" \
    --duration-in-seconds 86400 \
    --access-level Write \
    --query accessSas -o tsv)

echo "  Uploading $(( VHD_SIZE / 1024 / 1024 )) MB..."
azcopy copy "$VHD" "$SAS" --blob-type PageBlob

az disk revoke-access --resource-group "$RG" --name "$DISK_NAME" -o none
echo "  Upload complete."

# ---- 3. Create gallery + image definition ----
echo "[3/5] Creating image gallery..."
az sig create --resource-group "$RG" --gallery-name "$GALLERY" --location "$REGION" -o none 2>/dev/null || true

az sig image-definition create \
    --resource-group "$RG" \
    --gallery-name "$GALLERY" \
    --gallery-image-definition "$IMAGE_DEF" \
    --publisher "RuonLabs" \
    --offer "TOPRFNode" \
    --sku "sealed-v1" \
    --os-type Linux \
    --os-state Generalized \
    --hyper-v-generation V2 \
    --features "SecurityType=ConfidentialVMSupported" \
    --location "$REGION" \
    -o none 2>/dev/null || true

DISK_ID=$(az disk show --resource-group "$RG" --name "$DISK_NAME" --query id -o tsv)

VERSION="1.0.$(date +%Y%m%d%H%M%S | cut -c9-)"
az sig image-version create \
    --resource-group "$RG" \
    --gallery-name "$GALLERY" \
    --gallery-image-definition "$IMAGE_DEF" \
    --gallery-image-version "$VERSION" \
    --location "$REGION" \
    --os-snapshot "$DISK_ID" \
    -o none

IMAGE_ID=$(az sig image-version show \
    --resource-group "$RG" \
    --gallery-name "$GALLERY" \
    --gallery-image-definition "$IMAGE_DEF" \
    --gallery-image-version "$VERSION" \
    --query id -o tsv)
echo "  Image: $IMAGE_ID"

# ---- 4. Launch CVMs (if requested) ----
if [[ $NUM_NODES -gt 0 ]]; then
    echo "[4/5] Launching $NUM_NODES CVMs..."

    # Create NSG with port 3001
    NSG_NAME="toprf-nsg"
    az network nsg create --resource-group "$RG" --name "$NSG_NAME" --location "$REGION" -o none 2>/dev/null || true
    az network nsg rule create \
        --resource-group "$RG" \
        --nsg-name "$NSG_NAME" \
        --name AllowTOPRF \
        --priority 1010 \
        --direction Inbound \
        --access Allow \
        --protocol Tcp \
        --destination-port-ranges 3001 \
        -o none 2>/dev/null || true

    for i in $(seq 1 $NUM_NODES); do
        VM_NAME="toprf-node-$i"
        echo "  Launching $VM_NAME..."
        az vm create \
            --resource-group "$RG" \
            --name "$VM_NAME" \
            --location "$REGION" \
            --size "$VM_SIZE" \
            --image "$IMAGE_ID" \
            --security-type ConfidentialVM \
            --os-disk-security-encryption-type VMGuestStateOnly \
            --enable-vtpm true \
            --enable-secure-boot true \
            --admin-username azureuser \
            --generate-ssh-keys \
            --public-ip-sku Standard \
            --nsg "$NSG_NAME" \
            --query '{name:name, ip:publicIpAddress}' \
            -o table
    done
else
    echo "[4/5] Skipping VM launch (use --nodes N to launch)"
fi

# ---- 5. Summary ----
echo ""
echo "[5/5] Done."
echo ""
echo "=========================================="
echo "  Deployment Summary"
echo "=========================================="
echo "  Resource group: $RG"
echo "  Region:         $REGION"
echo "  Image version:  $VERSION"
echo "  Image ID:       $IMAGE_ID"
echo ""
if [[ $NUM_NODES -gt 0 ]]; then
    echo "  Launched VMs:"
    az vm list --resource-group "$RG" -d --query '[].{name:name, ip:publicIps, state:powerState}' -o table
fi
echo ""
echo "  To launch more nodes:"
echo "    az vm create --resource-group $RG --name toprf-node-N \\"
echo "      --size $VM_SIZE --image $IMAGE_ID \\"
echo "      --security-type ConfidentialVM \\"
echo "      --os-disk-security-encryption-type VMGuestStateOnly \\"
echo "      --enable-vtpm true --enable-secure-boot true"
echo "=========================================="

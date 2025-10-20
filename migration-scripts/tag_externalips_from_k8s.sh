#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <cluster-id>"
    exit 1
fi

cluster_id=$1

echo "Fetching ExternalIP resources from Kubernetes..."
externalips=$(kubectl get externalips.kubestatic.quortex.io -o json)

# Count the number of ExternalIP resources in the cluster
count=$(echo "$externalips" | jq '.items | length')
echo "Found $count ExternalIP resources"

# Loop over each ExternalIP resource and tag the corresponding EIP
# with the instance ID of the node it is attached to
#
# We encode the row in base64 to avoid issues with special characters
# and decode it to extract the values we need
for row in $(echo "${externalips}" | jq -r '.items[] | @base64'); do
    # Helper function to extract values from the base64 encoded row
    _jq() {
        echo "${row}" | base64 --decode | jq -r "${1}"
    }

    name=$(_jq '.metadata.name')
    allocation_id=$(_jq '.status.addressID')
     existing_auto_assign=$(_jq '.metadata.labels["kubestatic.quortex.io/externalip-auto-assign"]')

    if [[ -z "$allocation_id" ]]; then
        echo "Could not find addresse ID for externalIP $name"
        continue
    fi

 # Add label auto-assign only if missing
    if [[ -z "$existing_auto_assign" || "$existing_auto_assign" == "null" ]]; then
        echo "Adding label kubestatic.quortex.io/externalip-auto-assign=true to $name"
        kubectl label externalips.kubestatic.quortex.io "$name" \
        'kubestatic.quortex.io/externalip-auto-assign=true' \
        --overwrite=false
    else
        echo "Label present on $name: kubestatic.quortex.io/externalip-auto-assign=$existing_auto_assign"
    fi
    
    echo "Tagging $allocation_id (EIP) with:"
    echo "    kubestatic.quortex.io/managed: true"
    echo "    kubestatic.quortex.io/external-ip-name: $name"
    echo "    kubestatic.quortex.io/cluster-id: $cluster_id"

    aws ec2 create-tags \
        --resources "$allocation_id" \
        --tags \
        Key=kubestatic.quortex.io/managed,Value=true \
        Key=kubestatic.quortex.io/external-ip-name,Value="$name" \
        Key=kubestatic.quortex.io/cluster-id,Value="$cluster_id"

    echo "Tagged $allocation_id successfully"
done
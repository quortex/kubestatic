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
    node_name=$(_jq '.spec.nodeName')

    # Skip ExternalIP resources that are not attached to a node
    if [[ "$node_name" == "null" ]]; then
        echo "Skipping $name no node_name, ExternalIP should be in reserved state"
        continue
    fi

    echo "Resolving EC2 instance ID for node: $node_name..."
    # Fetch the instance ID of the node the ExternalIP is attached to
    instance_id=$(aws ec2 describe-instances \
        --filters "Name=private-dns-name,Values=$node_name" \
        --query "Reservations[].Instances[].InstanceId" \
        --output text)

    if [[ -z "$instance_id" ]]; then
        echo "Could not find instance ID for node $node_name"
        continue
    fi

    echo "Tagging $allocation_id (EIP) with:"
    echo "    kubestatic.quortex.io/managed: true"
    echo "    kubestatic.quortex.io/instance-id: $instance_id"
    echo "    kubestatic.quortex.io/external-ip-name: $name"
    echo "    kubestatic.quortex.io/cluster-id: $cluster_id"

    aws ec2 create-tags \
        --resources "$allocation_id" \
        --tags \
        Key=kubestatic.quortex.io/managed,Value=true \
        Key=kubestatic.quortex.io/instance-id,Value="$instance_id" \
        Key=kubestatic.quortex.io/external-ip-name,Value="$name" \
        Key=kubestatic.quortex.io/cluster-id,Value="$cluster_id"

    echo "Tagged $allocation_id successfully"
done

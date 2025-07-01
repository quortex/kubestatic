#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <cluster-id>"
    exit 1
fi

cluster_id=$1

echo "Fetching FirewallRule resources from Kubernetes..."
firewallrules=$(kubectl get firewallrules.kubestatic.quortex.io -o json)

count=$(echo "$firewallrules" | jq '.items | length')
echo "Found $count FirewallRule resources"

for row in $(echo "${firewallrules}" | jq -r '.items[] | @base64'); do
    _jq() {
        echo "${row}" | base64 --decode | jq -r "${1}"
    }

    name=$(_jq '.metadata.name')
    sg_id=$(_jq '.status.firewallRuleID')
    instance_id=$(_jq '.status.instanceID')
    node_name=$(_jq '.spec.nodeName')

    if [[ "$sg_id" == "null" || "$instance_id" == "null" || "$node_name" == "null" ]]; then
        echo "Skipping $name — missing sg_id, instance_id, or node_name"
        continue
    fi

    echo "Tagging Security Group $sg_id with:"
    echo "    kubestatic.quortex.io/managed: true"
    echo "    kubestatic.quortex.io/instance-id: $instance_id"
    echo "    kubestatic.quortex.io/node-name: $node_name"
    echo "    kubestatic.quortex.io/cluster-id: $cluster_id"

    aws ec2 create-tags \
        --resources "$sg_id" \
        --tags \
        Key=kubestatic.quortex.io/managed,Value=true \
        Key=kubestatic.quortex.io/instance-id,Value="$instance_id" \
        Key=kubestatic.quortex.io/node-name,Value="$node_name" \
        Key=kubestatic.quortex.io/cluster-id,Value="$cluster_id"

    echo "Tagged $sg_id successfully"
done

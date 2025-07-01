# kubestatic

![Version: 0.13.0-rc.8](https://img.shields.io/badge/Version-0.13.0--rc.8-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.13.0-rc.8](https://img.shields.io/badge/AppVersion-0.13.0--rc.8-informational?style=flat-square)

An operator to manage the lifecycle of public cloud providers resources needed to expose endpoints on public nodes.

## Overview
This project is an operator that allows Kubernetes to automatically manage the lifecycle of public cloud providers resources needed to expose endpoints on public nodes.

The standard use case for this tool is to provision external IPs on public nodes as well as firewall rules allowing to determine access permissions on these nodes.

## Prerequisites

### <a id="Prerequisites_AWS"></a>AWS
To be used with AWS and interact with EC2 resources, an AWS account with the following permissions is required:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllObjectActions",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:CreateSecurityGroup",
                "ec2:DeleteSecurityGroup",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:RevokeSecurityGroupEgress",
                "ec2:DescribeAddresses",
                "ec2:AllocateAddress",
                "ec2:ReleaseAddress",
                "ec2:AssociateAddress",
                "ec2:DisassociateAddress",
                "ec2:DescribeInstances",
                "ec2:ModifyInstanceAttribute",
                "ec2:DescribeNetworkInterfaces",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:CreateTags"
            ],
            "Resource": "*"
        }
    ]
}
```

## Installation

1. Add kubestatic helm repository

```sh
helm repo add kubestatic https://quortex.github.io/kubestatic
```

2. Deploy the appropriate release in desired namespace.

```sh
kubectl create namespace kubestatic-system
helm install kubestatic kubestatic/kubestatic -n kubestatic-system
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| cloudProvider | string | `"aws"` | The desired cloud provider (only AWS at the moment). |
| clusterId | string | `""` | The cluster ID to be used for the kubestatic deployment. |
| vpcId | string | `""` | The VPC ID of the instance kubestatic is deployed in. |
| preventEIPDeallocation | bool | `false` | Prevent EIP deallocation on nodes auto-assigned ExternalIPs. |
| nodeMinReconciliationInterval | string | `"10s"` | The minimum duration to wait between two reconciliations for the same node. |
| nodeReconciliationRequeueInterval | string | `"1m"` | The duration for which nodes are automatically reconciled. |
| aws.region | string | `""` | the region in which the cluster resides. |
| aws.accessKeyID | string | `""` | the access key id of a user with necessary permissions. |
| aws.secretAccessKey | string | `""` | the secret access key of a user with necessary permissions. |
| manager.image.repository | string | `"eu.gcr.io/quortex-registry-public/kubestatic"` | kubestatic manager image repository. |
| manager.image.tag | string | `""` | kubestatic manager image tag. |
| manager.image.pullPolicy | string | `"IfNotPresent"` | kubestatic manager image pull policy. |
| manager.resources | object | `{}` | kubestatic manager container required resources. |
| manager.securityContext | object | `{}` | kubestatic manager container security contexts |
| manager.extraArgs | list | `[]` | kubestatic manager additional arguments to the entrypoint. |
| kubeRBACProxy.enabled | bool | `true` |  |
| kubeRBACProxy.image.repository | string | `"gcr.io/kubebuilder/kube-rbac-proxy"` | kube-rbac-proxy image repository. |
| kubeRBACProxy.image.tag | string | `"v0.8.0"` | kube-rbac-proxy image tag. |
| kubeRBACProxy.image.pullPolicy | string | `"IfNotPresent"` | kube-rbac-proxy image pull policy. |
| kubeRBACProxy.resources | object | `{}` | kube-rbac-proxy container required resources. |
| replicaCount | int | `1` | Number of desired pods. |
| podSecurityContext | object | `{}` | Security contexts to set for all containers of the pod. |
| imagePullSecrets | list | `[]` | A list of secrets used to pull containers images. |
| nameOverride | string | `""` | Helm's name computing override. |
| fullnameOverride | string | `""` | Helm's fullname computing override. |
| podAnnotations | object | `{}` | Annotations to be added to pods. |
| nodeSelector | object | `{}` | Node labels for Kubestitute pod assignment. |
| tolerations | list | `[]` | Node tolerations for Kubestitute scheduling to nodes with taints. |
| affinity | object | `{}` | Affinity for Kubestitute pod assignment. |
| serviceAccount | object | `{"annotations":{}}` | ServiceAccount setup |
| serviceAccount.annotations | object | `{}` | Annotations added to the ServiceAccount. |
| serviceMonitor.enabled | bool | `false` | Create a prometheus operator ServiceMonitor. |
| serviceMonitor.additionalLabels | object | `{}` | Labels added to the ServiceMonitor. |
| serviceMonitor.annotations | object | `{}` | Annotations added to the ServiceMonitor. |
| serviceMonitor.interval | string | `""` | Override prometheus operator scrapping interval. |
| serviceMonitor.scrapeTimeout | string | `""` | Override prometheus operator scrapping timeout. |
| serviceMonitor.relabelings | list | `[]` | Relabellings to apply to samples before scraping. |


# Helm repository for cert-manager-webhook-infoblox-wapi

[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager-webhook-infoblox-wapi)](https://artifacthub.io/packages/search?repo=cert-manager-webhook-infoblox-wapi)

Sources and further documentation can be found at [https://github.com/luisico/cert-manager-webhook-infoblox-wapi](https://github.com/luisico/cert-manager-webhook-infoblox-wapi).

## Usage

[Helm](https://helm.sh) must be installed to use the charts. Please refer to Helm's [documentation](https://helm.sh/docs) to get started.

Once Helm has been set up correctly, add the repo as follows:
```
helm repo add cert-manager-webhook-infoblox-wapi https://luisico.github.io/cert-manager-webhook-infoblox-wapi
```

If you had already added this repo earlier, run `helm repo update` to retrieve the latest versions of the packages. You can then run `helm search repo <alias>` to see the charts.

To install the chart:

```
helm install my-release-name  cert-manager-webhook-infoblox-wapi/cert-manager-webhook-infoblox-wapi
```

To uninstall the chart:

```
helm delete my-release-name
```

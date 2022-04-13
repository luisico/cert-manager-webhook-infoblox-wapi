# ACME webhook for InfoBlox WAPI

An InfoBlox WAPI webhook for cert-manager.

This project provides a custom [ACME DNS01 Challenge Provider](https://cert-manager.io/docs/configuration/acme/dns01) as a webhook for [cert-manager](https://cert-manager.io/). This webhook integrates cert-manager with InfoBlox WAPI is a REST API. You can learn more about WAPI in this [PDF](https://www.infoblox.com/wp-content/uploads/infoblox-deployment-infoblox-rest-api.pdf).

This implementation is based on [infoblox-go-client](https://github.com/infobloxopen/infoblox-go-client) library.

This project is a fork of https://github.com/cert-manager/webhook-example.

## Requirements

- InfoBlox GRID installation with WAPI 2.5 or above
- helm v3
- kubernetes 1.21+
- cert-manager 1.5+

Note that other versions might work, but have not been tested.

## Installation

1. Cert-manager
2. Infoblox-wapi webhook
3. Issuer

### Install Cert-manager

Follow [instructions](https://cert-manager.io/docs/installation/) to install cert-manager.

### Install infoblox-wapi webhook

At a minimum you will need to customize `groupName` with your own group name. See [deploy/cert-manager-webhook-infoblox-wapi/values.yaml](./deploy/cert-manager-webhook-infoblox-wapi/values.yaml) for an in-depth explanation and other values that might require tweaking. With either method below, follow [helm instructions](https://helm.sh/docs/intro/using_helm/#customizing-the-chart-before-installing) to customize your deployment.


Docker images are stored in GitHub's [ghcr.io](ghcr.io) registry, specifically at [ghcr.io/luisico/cert-manager-webhook-infoblox-wapi](ghcr.io/luisico/cert-manager-webhook-infoblox-wapi).

#### Using the public helm chart

```
helm repo add cert-manager-webhook-infoblox-wapi https://luisico.github.io/cert-manager-webhook-infoblox-wapi
helm -n cert-manager install cert-manager-webhook-infoblox-wapi
```

#### From source

Check out this repository and run the following command:

```
helm -n cert-manager install webhook-infoblox-wapi deploy/cert-manager-webhook-infoblox-wapi
```

#### Values
| Name                           | Description                                                                                          | Value
| ------------------------------ | ---------------------------------------------------------------------------------------------------- | -----
| nameOverride                   | String to partially override chart name. | ""
| fullNameOverride               | String to fully override chart fullname. | ""
| groupName                      | The GroupName here is used to identify your company or business unit that created this webhook. This name will need to be referenced in each Issuer's `webhook` stanza to inform cert-manager of where to send ChallengePayload resources in order to solve the DNS01 challenge. This group name should be **unique**, hence using your own company's domain # here is recommended. | acme.mycompany.com
| certManager.namespace          | Namespace where cert-manager is deployed. | cert-manager
| certManager.serviceAccountName | Service account name of cert-manager. | cert-manager
| rootCACertificate.duration     | Duration of root CA certificate | 43800h
| servingCertificate.duration    | Duration of serving certificate | 8760h
| image.repository               | Deployment image repository | ghcr.io/luisico/cert-manager-webhook-infoblox-wapi
| image.tag                      | Deployment image tag | 1.5
| image.pullPolicy               | Image pull policy | IfNotPresent
| service.type                   | Service type to expose | ClusterIP
| service.port                   | Service port to expose | 443
| resources                      | Deployment resource limits | {}
| nodeSelector                   | Deployment node selector object | {}
| tolerations                    | Deployment tolerations | []
| affinity                       | Deployment affinity | {}

### Install a Issuer

To install your issuer you will need the following resources:
- `Issuer` or `ClusterIssuer`
- `Secret` to store infoblox credentials. `username` and `password` can be defined in the same or different secrets.
- `Role` and `RoleBinding` to allow the webhook to access the secret

An example follows:

```
---
apiVersion: v1
kind: Secret
metadata:
  name: infoblox-credentials
  namespace: cert-manager
type: Opaque
data:
  username: dXNlcm5hbWUK      # base64 decoded: "username"
  password: cGFzc3dvcmQK      # base64 decoded: "password"

---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    email: your.email@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-account-key
    solvers:
    - dns01:
        webhook:
          groupName: acme.mycompany.com
          solverName: infoblox-wapi
          config:
            host: infoblox.fqdn
            view: "InfoBlox View"
            usernameSecretRef:
              name: infoblox-credentials
              key: username
            passwordSecretRef:
              name: infoblox-credentials
              key: password

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: webhook-infoblox-wapi:secret-reader
  namespace: cert-manager
rules:
  - apiGroups: [""]
    resources:
      - secrets
    resourceNames:
      - infoblox-credentials
    verbs:
      - get
      - watch

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: webhook-infoblox-wapi:secret-reader
  namespace: cert-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: webhook-infoblox-wapi:secret-reader
subjects:
  - apiGroup: ""
    kind: ServiceAccount
    name: webhook-infoblox-wapi
    namespace: cert-manager
```

Remember to adjust the previous snippet:
- For the `Secret`: change username and password.
- For the `ClusterIssuer`:
  - `email` with your email address.
  - `server` with LE's production server when ready.
  - `groupName` with the same group name selected while installing the webhook earlier.
  - `config.host` with the FQDN or IP address of your InfoBlox WAPI server.
  - `config.view` with the DNS View you want to manipulate in your InfoBlox server.

This is the full list of webhook configuration options:
- `host`: FQDN or IP address of the InfoBlox server.
- `port`: Port of the InfoBlox server (default: 443).
- `version`: Version of the InfoBlox server (default: 2.5).
- `usernameSecretRef`: Reference to the secret name holding the username for the InfoBlox server
- `passwordSecretRef`: Reference to the secret name holding the password for the InfoBlox server
- `view`: DNS View in the InfoBlox server to manipulate TXT records in.
- `sslVerify`: Verify SSL connection (default: false).
- `httpRequestTimeout`: Timeout for HTTP request to the InfoBlox server, in seconds (default: 60).
- `httpPoolConnections`: Maximum number of connections to the InfoBlox server (default: 10).

Now you can create a certificate, for example:

```
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: infoblox-wapi-test
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
  secretName: infoblox-wapi-test-tls
```

## Running the test suite

Requirements:

- go >= 1.16

First create you own `config.json` and `credentials.yaml` inside `testdata/infoblox-wapi/` based on the corresponding `.sample` files. The values in `config.json` correspond to the webhook `config` section in the example `ClusterIssuer` above, while `credentials.yaml` will create a secret. Ensure that you fill in the values for the test to connect to an InfoBlox instance.

You can then run the test suite with:

```bash
TEST_ZONE_NAME=example.com. make test
```

## Contributions

I you would like to contribute to this projects, please, open a PR via GitHub. Thanks.

## License

This project inherits the Apache 2.0 license from https://github.com/cert-manager/webhook-example.

Modifications to files are listed in [NOTICE](./NOTICE).

## Author

Luis Gracia while at [The Rockefeller University](http://www.rockefeller.edu):
- lgracia [at] rockefeller.edu
- lgracia [at] gmail.com
- GitHub at [luisico](https://github.com/luisico)

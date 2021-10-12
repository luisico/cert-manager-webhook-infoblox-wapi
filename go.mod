module github.com/luisico/cert-manager-webhook-infoblox-wapi

go 1.16

require (
	github.com/infobloxopen/infoblox-go-client/v2 v2.0.0
	github.com/jetstack/cert-manager v1.5.4
	github.com/miekg/dns v1.1.34
	github.com/stretchr/testify v1.7.0
	k8s.io/apiextensions-apiserver v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
)

// Apply same replacements as in https://github.com/jetstack/cert-manager/blob/v1.5.4/go.mod

replace golang.org/x/net => golang.org/x/net v0.0.0-20210224082022-3d97a244fca7

replace github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1

replace k8s.io/code-generator => github.com/kmodules/code-generator v0.21.1-rc.0.0.20210428003838-7eafae069eb0

replace k8s.io/gengo => github.com/kmodules/gengo v0.0.0-20210428002657-a8850da697c2

replace k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7

replace google.golang.org/grpc => google.golang.org/grpc v1.29.1

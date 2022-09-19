module sigs.k8s.io/cloud-provider-huaweicloud

go 1.13

require (
	github.com/chnsz/golangsdk v0.0.0-20220831020503-4997d76976f9
	github.com/kubernetes-csi/csi-lib-utils v0.11.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.7.0
	github.com/unknwon/com v1.0.1
	golang.org/x/crypto v0.0.0-20211202192323-5770296d904e // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1
	google.golang.org/grpc v1.38.0
	gopkg.in/gcfg.v1 v1.2.3
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.22.0
	k8s.io/apimachinery v0.19.14
	k8s.io/apiserver v0.19.14
	k8s.io/cloud-provider v0.19.14
	k8s.io/component-base v0.22.0
	k8s.io/klog/v2 v2.9.0
	k8s.io/kubernetes v1.19.14
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
)

replace (
	google.golang.org/grpc => google.golang.org/grpc v1.29.1
	k8s.io/api => k8s.io/api v0.19.14
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.14
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.14
	k8s.io/apiserver => k8s.io/apiserver v0.19.14
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.14
	k8s.io/client-go => k8s.io/client-go v0.19.14
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.14
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.19.14
	k8s.io/code-generator => k8s.io/code-generator v0.19.14
	k8s.io/component-base => k8s.io/component-base v0.19.0
	k8s.io/controller-manager => k8s.io/controller-manager v0.19.14
	k8s.io/cri-api => k8s.io/cri-api v0.19.14
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.19.14
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.19.14
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.19.14
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.19.14
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.19.14
	k8s.io/kubectl => k8s.io/kubectl v0.19.14
	k8s.io/kubelet => k8s.io/kubelet v0.19.14
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.19.14
	k8s.io/metrics => k8s.io/metrics v0.19.14
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.19.14
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.19.14
	k8s.io/sample-controller => k8s.io/sample-controller v0.19.14
)

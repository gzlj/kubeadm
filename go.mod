module github.com/gzlj/kubeadm

go 1.13

require (
	github.com/googleapis/gnostic v0.4.1
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/pkg/errors v0.9.1
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	k8s.io/api v0.19.3
	k8s.io/apimachinery v0.19.3
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/cluster-bootstrap v0.19.2
	k8s.io/klog v1.0.0
	k8s.io/utils v0.0.0-20201015054608-420da100c033 // indirect
)

replace github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.0.0-20170729233727-0c5108395e2d

/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// +k8s:deepcopy-gen=package
// +groupName=kubeadm.k8s.io

// Package kubeadm is the package that contains the libraries that drive the kubeadm binary.
// kubeadm is responsible for handling a Kubernetes cluster's lifecycle.
package kubeadm // import "github.com/gzlj/kubeadm/cmd/kubeadm/app/apis/kubeadm"
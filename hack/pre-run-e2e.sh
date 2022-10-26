#!/usr/bin/env bash

# Copyright 2022 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

if [[ "${REGISTRY_USER_NAME}" = "" ]] || [[ "${REGISTRY_PASSWORD}" = "" ]]; then
  echo "REGISTRY_USER_NAME and REGISTRY_PASSWORD can not be empty, please set it"
  exit 1
fi

export REGISTRY_SERVER_ADDRESS=swr.ap-southeast-1.myhuaweicloud.com
# The images will be automatically deleted after 3 days in dev-registry.
export REGISTRY=${REGISTRY_SERVER_ADDRESS}/dev-registry
export VERSION=`git rev-parse --short HEAD`

echo -e "\nBuild images"
make upload-images

echo -e "\nCheck cloud-config secret"
count=`kubectl get -n kube-system secret cloud-config | grep cloud-config | wc -l`
if [[ "$count" -ne 1 ]]; then
  echo "Please create a secret with the name: cloud-config."
  exit 1
fi

# Remove the existing provider if it exists.
kubectl delete -n kube-system daemonset --ignore-not-found=true huawei-cloud-controller-manager
kubectl wait --for=delete -n kube-system pod -l k8s-app=huawei-cloud-controller-manager --timeout=30s

echo -e "\nDeploy huawei-cloud-controller-manager"
cat << EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: system:cloud-controller-manager
rules:
  - resources:
      - tokenreviews
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
    apiGroups:
      - authentication.k8s.io
  - resources:
      - configmaps
      - endpoints
      - pods
      - services
      - secrets
      - serviceaccounts
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
    apiGroups:
      - ''
  - resources:
      - nodes
    verbs:
      - get
      - list
      - watch
      - delete
      - patch
      - update
    apiGroups:
      - ''
  - resources:
      - services/status
      - pods/status
    verbs:
      - update
      - patch
    apiGroups:
      - ''
  - resources:
      - nodes/status
    verbs:
      - patch
      - update
    apiGroups:
      - ''
  - resources:
      - events
      - endpoints
    verbs:
      - create
      - patch
      - update
    apiGroups:
      - ''
  - resources:
      - leases
    verbs:
      - get
      - update
      - create
      - delete
    apiGroups:
      - coordination.k8s.io
  - resources:
      - customresourcedefinitions
    verbs:
      - get
      - update
      - create
      - delete
    apiGroups:
      - apiextensions.k8s.io
  - resources:
      - ingresses
    verbs:
      - get
      - list
      - watch
      - update
      - create
      - patch
      - delete
    apiGroups:
      - networking.k8s.io
  - resources:
      - ingresses/status
    verbs:
      - update
      - patch
    apiGroups:
      - networking.k8s.io
  - resources:
      - endpointslices
    verbs:
      - get
      - list
      - watch
    apiGroups:
      - discovery.k8s.io
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloud-controller-manager
  namespace: kube-system
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:cloud-controller-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:cloud-controller-manager
subjects:
  - kind: ServiceAccount
    name: cloud-controller-manager
    namespace: kube-system
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: huawei-cloud-controller-manager
  namespace: kube-system
  labels:
    k8s-app: huawei-cloud-controller-manager
spec:
  selector:
    matchLabels:
      k8s-app: huawei-cloud-controller-manager
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        k8s-app: huawei-cloud-controller-manager
    spec:
      nodeSelector:
        node-role.kubernetes.io/master: ""
      securityContext:
        runAsUser: 1001
      tolerations:
        - key: node.cloudprovider.kubernetes.io/uninitialized
          value: "true"
          effect: NoSchedule
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      serviceAccountName: cloud-controller-manager
      containers:
        - name: huawei-cloud-controller-manager
          image: ${REGISTRY}/huawei-cloud-controller-manager:${VERSION}
          args:
            - /bin/huawei-cloud-controller-manager
            - --v=5
            - --cloud-config=/etc/config/cloud.conf
            - --cloud-provider=huaweicloud
            - --use-service-account-credentials=true
            - --bind-address=127.0.0.1
          volumeMounts:
            - mountPath: /etc/kubernetes
              name: k8s-certs
              readOnly: true
            - mountPath: /etc/ssl/certs
              name: ca-certs
              readOnly: true
            - mountPath: /etc/config
              name: cloud-config-volume
              readOnly: true
            - mountPath: /usr/libexec/kubernetes/kubelet-plugins/volume/exec
              name: flexvolume-dir
          resources:
            requests:
              cpu: 200m
      hostNetwork: true
      volumes:
      - hostPath:
          path: /usr/libexec/kubernetes/kubelet-plugins/volume/exec
          type: DirectoryOrCreate
        name: flexvolume-dir
      - hostPath:
          path: /etc/kubernetes
          type: DirectoryOrCreate
        name: k8s-certs
      - hostPath:
          path: /etc/ssl/certs
          type: DirectoryOrCreate
        name: ca-certs
      - name: cloud-config-volume
        secret:
          secretName: cloud-config
EOF

kubectl wait --for=condition=ready -n kube-system pod -l k8s-app=huawei-cloud-controller-manager --timeout=30s

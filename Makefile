# Copyright 2020 The Kubernetes Authors.
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

GOOS ?= $(shell go env GOOS)
SOURCES := $(shell find . -type f  -name '*.go')
LDFLAGS := ""

# Images management
REGISTRY_USER_NAME?=""
REGISTRY_PASSWORD?=""
REGISTRY_SERVER_ADDRESS?=""
REGISTRY?="${REGISTRY_SERVER_ADDRESS}/k8s-cloudcontrollermanager"

clean:
	rm -rf huawei-cloud-controller-manager

verify:
	./hack/verify.sh

.PHONY: test
test:
	go test ./pkg/...

.PHONY: fmt
fmt:
	./hack/check-format.sh

huawei-cloud-controller-manager: $(SOURCES)
	CGO_ENABLED=0 GOOS=$(GOOS) go build \
		-ldflags $(LDFLAGS) \
		-o huawei-cloud-controller-manager \
		./cmd/cloud-controller-manager

image-huawei-cloud-controller-manager: huawei-cloud-controller-manager
	cp huawei-cloud-controller-manager ./cluster/images/cloud-controller-manager \
	docker build -t $(REGISTRY)/huawei-cloud-controller-manager:$(VERSION) cluster/images/cloud-controller-manager \
	rm ./cluster/images/cloud-controller-manager/huawei-cloud-controller-manager

upload-image-huawei-cloud-controller-manager:
	@echo "push images to $(REGISTRY)"
	docker login -u ${REGISTRY_USER_NAME} -p ${REGISTRY_PASSWORD} ${REGISTRY_SERVER_ADDRESS}
	docker push ${REGISTRY}/huawei-cloud-controller-manager:${VERSION}

ccm:
	go build -tags netgo -o huawei-cloud-controller-manager ./cmd/cloud-controller-manager
ccm-image:ccm
	cp ./huawei-cloud-controller-manager ./cluster/images/cloud-controller-manager
	docker build cluster/images/cloud-controller-manager -t chengxiangdong/huawei-cloud-controller-manager:latest
	docker push houpeng/huawei-cloud-controller-manager:latest
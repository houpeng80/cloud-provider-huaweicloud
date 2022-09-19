/*
Copyright 2022 The Kubernetes Authors.

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

package huaweicloud

import (
	"fmt"
	"io"

	v1 "k8s.io/api/core/v1"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/cloudprovider/huaweicloud/services"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"
)

const (
	// ProviderName is the name of the openstack provider
	ProviderName = "huaweicloud"
)

type HuaweiCloud struct {
	config *config.Config

	loadbalancerService services.LBService

	loadbalancerSharedSvs    services.LBSharedService
	loadbalancerDedicatedSvs services.LBDedicatedService

	computeService  services.ComputeService
	publicIpService services.PublicIpService
}

func (h *HuaweiCloud) GetLBService(service *v1.Service) (services.LBService, error) {
	class := service.Annotations[ServiceAnnotationELBClass]
	switch class {
	case "elasticity":
		klog.Infof("Load balancer Version I for service %v", service.Name)
		return &h.loadbalancerSharedSvs, nil
	case "union":
		klog.Infof("Shared load balancer for service %v", service.Name)
		return &h.loadbalancerSharedSvs, nil
	case "performance":
		klog.Infof("Dedicated load balancer for service %v", service.Name)
		return &h.loadbalancerDedicatedSvs, nil
	case "dnat":
		klog.Infof("DNAT for service %v", service.Name)
		return nil, nil
	default:
		return nil, fmt.Errorf("Load balancer version unknown")
	}

	return nil, fmt.Errorf("Load balancer version unknown")
}

func init() {
	cloudprovider.RegisterCloudProvider(ProviderName, func(cfgReader io.Reader) (cloudprovider.Interface, error) {
		cfg, err := config.ReadConfig(cfgReader)
		if err != nil {
			klog.Fatalf("failed to read config: %v", err)
			return nil, err
		}

		cloud := HuaweiCloud{
			config:                   cfg,
			loadbalancerSharedSvs:    services.LBSharedService{Config: cfg},
			loadbalancerDedicatedSvs: services.LBDedicatedService{Config: cfg},
			computeService:           services.ComputeService{Config: cfg},
			publicIpService:          services.PublicIpService{Config: cfg},
		}
		return &cloud, nil
	})
}

func (h *HuaweiCloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return &LB{HuaweiCloud: h, Opts: &h.config.LoadBalancer}, true
}

func (h *HuaweiCloud) Instances() (cloudprovider.Instances, bool) {
	return &Instances{HuaweiCloud: h}, false
}

func (h *HuaweiCloud) InstancesV2() (cloudprovider.InstancesV2, bool) {
	return &Instances{HuaweiCloud: h}, false
}

func (h *HuaweiCloud) Zones() (cloudprovider.Zones, bool) {
	return &Zones{HuaweiCloud: h}, false
}

func (h *HuaweiCloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

func (h *HuaweiCloud) Routes() (cloudprovider.Routes, bool) {
	return nil, false
}

func (h *HuaweiCloud) ProviderName() string {
	return ProviderName
}

func (h *HuaweiCloud) HasClusterID() bool {
	return true
}

func (h *HuaweiCloud) Initialize(clientBuilder cloudprovider.ControllerClientBuilder, stop <-chan struct{}) {
}

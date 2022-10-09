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

package services

import (
	"fmt"
	"net"
	"sort"

	"github.com/chnsz/golangsdk"
	"github.com/chnsz/golangsdk/openstack/compute/v2/extensions/attachinterfaces"
	"github.com/chnsz/golangsdk/openstack/ecs/v1/cloudservers"
	"github.com/chnsz/golangsdk/pagination"
	"github.com/mitchellh/mapstructure"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/common"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/utils"
)

type ComputeService struct {
	Config *config.Config
}

func (s *ComputeService) Get(instanceID string) (*cloudservers.CloudServer, error) {
	client, err := s.getEcsV1Client()
	if err != nil {
		return nil, err
	}

	cs, err := cloudservers.Get(client, instanceID).Extract()
	if err != nil {
		if common.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Error, ECS instance %s does not exist", instanceID)
		}
		return nil, status.Errorf(codes.Internal, "Error querying ECS instance details: %s", err)
	}
	return cs, nil
}

// GetByName query the instance matching the name, and return an error if none or more than one is found.
func (s *ComputeService) GetByName(name string) (*cloudservers.CloudServer, error) {
	client, err := s.getEcsV1Client()
	if err != nil {
		return nil, err
	}

	opts := cloudservers.ListOpts{
		Name: fmt.Sprintf("^%s$", name),
	}
	serverList := make([]cloudservers.CloudServer, 0, 1)
	err = cloudservers.List(client, opts).EachPage(func(page pagination.Page) (bool, error) {
		list, err := cloudservers.ExtractServers(page)
		if err != nil {
			return false, err
		}
		serverList = append(serverList, list...)

		if len(list) > 1 {
			return false, fmt.Errorf("multiple results where only one expected")
		}
		return true, nil
	})
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "Error querying servers by name: %s", err)
	}

	if len(serverList) == 0 {
		return nil, status.Errorf(codes.NotFound, "Error, not found any servers matched name: %s", name)
	}
	return &serverList[0], nil
}

func (s *ComputeService) ListInterfaces(instanceID string) ([]attachinterfaces.Interface, error) {
	client, err := s.getBmsV21Client()
	if err != nil {
		return nil, err
	}

	page, err := attachinterfaces.List(client, instanceID).AllPages()
	if err != nil {
		return nil, err
	}
	interfaces, err := attachinterfaces.ExtractInterfaces(page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error querying a list of server interfaces: %s", err)
	}

	return interfaces, err
}

func (s *ComputeService) BuildAddresses(srv *cloudservers.CloudServer, interfaces []attachinterfaces.Interface,
	networkingOpts config.NetworkingOpts) ([]v1.NodeAddress, error) {

	addrs := []v1.NodeAddress{}

	// parse private IP addresses first in an ordered manner
	for _, iface := range interfaces {
		for _, fixedIP := range iface.FixedIPs {
			if iface.PortState == "ACTIVE" {
				isIPv6 := net.ParseIP(fixedIP.IPAddress).To4() == nil
				if !(isIPv6 && networkingOpts.IPv6SupportDisabled) {
					addToNodeAddresses(&addrs,
						v1.NodeAddress{
							Type:    v1.NodeInternalIP,
							Address: fixedIP.IPAddress,
						},
					)
				}
			}
		}
	}

	// process public IP addresses
	if srv.AccessIPv4 != "" {
		addToNodeAddresses(&addrs,
			v1.NodeAddress{
				Type:    v1.NodeExternalIP,
				Address: srv.AccessIPv4,
			},
		)
	}

	if srv.AccessIPv6 != "" && !networkingOpts.IPv6SupportDisabled {
		addToNodeAddresses(&addrs,
			v1.NodeAddress{
				Type:    v1.NodeExternalIP,
				Address: srv.AccessIPv6,
			},
		)
	}

	// process the rest
	type Address struct {
		IPType string `mapstructure:"OS-EXT-IPS:type"`
		Addr   string
	}

	var addresses map[string][]Address
	err := mapstructure.Decode(srv.Addresses, &addresses)
	if err != nil {
		return nil, err
	}

	var networks []string
	for k := range addresses {
		networks = append(networks, k)
	}
	sort.Strings(networks)

	for _, network := range networks {
		for _, props := range addresses[network] {
			var addressType v1.NodeAddressType
			if props.IPType == "floating" {
				addressType = v1.NodeExternalIP
			} else if utils.Contains(networkingOpts.PublicNetworkName, network) {
				addressType = v1.NodeExternalIP
				// removing already added address to avoid listing it as both ExternalIP and InternalIP
				// may happen due to listing "private" network as "public" in CCM's Config
				removeFromNodeAddresses(&addrs,
					v1.NodeAddress{
						Address: props.Addr,
					},
				)
			} else {
				if len(networkingOpts.InternalNetworkName) == 0 || utils.Contains(networkingOpts.InternalNetworkName,
					network) {
					addressType = v1.NodeInternalIP
				} else {
					klog.V(4).Infof("[DEBUG] Node '%s' address '%s' "+
						"ignored due to 'internal-network-name' option", srv.Name, props.Addr)

					removeFromNodeAddresses(&addrs,
						v1.NodeAddress{
							Address: props.Addr,
						},
					)
					continue
				}
			}

			isIPv6 := net.ParseIP(props.Addr).To4() == nil
			if !(isIPv6 && networkingOpts.IPv6SupportDisabled) {
				addToNodeAddresses(&addrs,
					v1.NodeAddress{
						Type:    addressType,
						Address: props.Addr,
					},
				)
			}
		}
	}

	return addrs, nil
}

// addToNodeAddresses appends the NodeAddresses to the passed-by-pointer slice, only if they do not already exist.
func addToNodeAddresses(addresses *[]v1.NodeAddress, addAddresses ...v1.NodeAddress) {
	for _, add := range addAddresses {
		exists := false
		for _, existing := range *addresses {
			if existing.Address == add.Address && existing.Type == add.Type {
				exists = true
				break
			}
		}
		if !exists {
			*addresses = append(*addresses, add)
		}
	}
}

// removeFromNodeAddresses removes the NodeAddresses from the passed-by-pointer slice if they already exist.
func removeFromNodeAddresses(addresses *[]v1.NodeAddress, removeAddresses ...v1.NodeAddress) {
	var indexesToRemove []int
	for _, remove := range removeAddresses {
		for i := len(*addresses) - 1; i >= 0; i-- {
			existing := (*addresses)[i]
			if existing.Address == remove.Address && (existing.Type == remove.Type || remove.Type == "") {
				indexesToRemove = append(indexesToRemove, i)
			}
		}
	}
	for _, i := range indexesToRemove {
		if i < len(*addresses) {
			*addresses = append((*addresses)[:i], (*addresses)[i+1:]...)
		}
	}
}

func (s *ComputeService) getEcsV1Client() (*golangsdk.ServiceClient, error) {
	client, err := s.Config.EcsV1Client()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed create ECS V1 client: %s", err))
	}
	return client, nil
}

func (s *ComputeService) getEcsV21Client() (*golangsdk.ServiceClient, error) {
	client, err := s.Config.EcsV21Client()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed create ECS V1 client: %s", err))
	}
	return client, nil
}

func (s *ComputeService) getBmsV21Client() (*golangsdk.ServiceClient, error) {
	client, err := s.Config.BmsV21Client()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed create BMS V2.1 client: %s", err))
	}
	return client, nil
}

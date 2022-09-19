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
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/chnsz/golangsdk/openstack/ecs/v1/cloudservers"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/common"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/utils/metadata"
)

const (
	instanceShutoffStatus = "SHUTOFF"
)

var providerIDRegexp = regexp.MustCompile(`^` + ProviderName + `:///([^/]+)$`)

type Instances struct {
	*HuaweiCloud
}

// NodeAddresses returns the addresses of the specified instance.
func (i *Instances) NodeAddresses(ctx context.Context, name types.NodeName) ([]v1.NodeAddress, error) {
	klog.Infof("NodeAddresses(%v) called", name)
	instance, err := i.computeService.GetByName(string(name))
	if err != nil {
		return nil, err
	}
	return i.NodeAddressesByProviderID(ctx, instance.ID)
}

// NodeAddressesByProviderID returns the addresses of the specified instance.
// The instance is specified using the providerID of the node. The
// ProviderID is a unique identifier of the node. This will not be called
// from the node whose nodeaddresses are being queried. i.e. local metadata
// services cannot be used in this method to obtain nodeaddresses
func (i *Instances) NodeAddressesByProviderID(_ context.Context, providerID string) ([]v1.NodeAddress, error) {
	instanceID, err := parseInstanceID(providerID)
	if err != nil {
		return nil, err
	}

	interfaces, err := i.computeService.ListInterfaces(instanceID)
	if err != nil {
		return nil, err
	}

	instance, err := i.computeService.Get(instanceID)
	if err != nil {
		return nil, err
	}

	addresses, err := i.computeService.BuildAddresses(instance, interfaces, i.config.Networking)
	if err != nil {
		return nil, err
	}

	klog.Infof("NodeAddresses(ID: %v) => %v", providerID, addresses)
	return addresses, nil
}

// InstanceID returns the cloud provider ID of the node with the specified NodeName.
// Note that if the instance does not exist, we must return ("", cloudprovider.InstanceNotFound)
// cloudprovider.InstanceNotFound should NOT be returned for instances that exist but are stopped/sleeping
func (i *Instances) InstanceID(ctx context.Context, name types.NodeName) (string, error) {
	server, err := i.computeService.GetByName(string(name))
	if err != nil {
		return "", err
	}
	return "/" + server.ID, nil
}

// InstanceType returns the type of the specified instance.
func (i *Instances) InstanceType(_ context.Context, name types.NodeName) (string, error) {
	instance, err := i.computeService.GetByName(string(name))
	if err != nil {
		return "", err
	}

	return getInstanceFlavor(instance)
}

func getInstanceFlavor(instance *cloudservers.CloudServer) (string, error) {
	if len(instance.Flavor.Name) > 0 {
		return instance.Flavor.Name, nil
	}
	if len(instance.Flavor.ID) > 0 {
		return instance.Flavor.Name, nil
	}

	return "", fmt.Errorf("flavor name/id not found")
}

// InstanceTypeByProviderID returns the type of the specified instance.
func (i *Instances) InstanceTypeByProviderID(_ context.Context, providerID string) (string, error) {
	instanceID, err := parseInstanceID(providerID)
	if err != nil {
		return "", err
	}

	instance, err := i.computeService.Get(instanceID)
	if err != nil {
		return "", err
	}

	return getInstanceFlavor(instance)
}

// AddSSHKeyToAllInstances adds an SSH public key as a legal identity for all instances
// expected format for the key is standard ssh-keygen format: <protocol> <blob>
func (i *Instances) AddSSHKeyToAllInstances(ctx context.Context, user string, keyData []byte) error {
	return cloudprovider.NotImplemented
}

// CurrentNodeName returns the name of the node we are currently running on
// On most clouds (e.g. GCE) this is the hostname, so we provide the hostname
func (i *Instances) CurrentNodeName(_ context.Context, _ string) (types.NodeName, error) {
	m, err := metadata.Get(i.config.Metadata.SearchOrder)
	if err != nil {
		return "", err
	}
	return types.NodeName(m.Name), nil
}

// InstanceExistsByProviderID returns true if the instance for the given provider exists.
// If false is returned with no error, the instance will be immediately deleted by the cloud controller manager.
// This method should still return true for instances that exist but are stopped/sleeping.
func (i *Instances) InstanceExistsByProviderID(_ context.Context, providerID string) (bool, error) {
	instanceID, err := parseInstanceID(providerID)
	if err != nil {
		return false, err
	}

	_, err = i.computeService.Get(instanceID)
	if err != nil {
		if common.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// InstanceShutdownByProviderID returns true if the instance is shutdown in cloudprovider
func (i *Instances) InstanceShutdownByProviderID(_ context.Context, providerID string) (bool, error) {
	instanceID, err := parseInstanceID(providerID)
	if err != nil {
		return false, err
	}
	server, err := i.computeService.Get(instanceID)
	if err != nil {
		return false, err
	}

	return server.Status == instanceShutoffStatus, nil
}

// InstanceExists returns true if the instance for the given node exists according to the cloud provider.
// Use the node.name or node.spec.providerID field to find the node in the cloud provider.
func (i *Instances) InstanceExists(ctx context.Context, node *v1.Node) (bool, error) {
	return i.InstanceExistsByProviderID(ctx, node.Spec.ProviderID)
}

// InstanceShutdown returns true if the instance is shutdown according to the cloud provider.
// Use the node.name or node.spec.providerID field to find the node in the cloud provider.
func (i *Instances) InstanceShutdown(ctx context.Context, node *v1.Node) (bool, error) {
	return i.InstanceShutdownByProviderID(ctx, node.Spec.ProviderID)
}

// InstanceMetadata returns the instance's metadata. The values returned in InstanceMetadata are
// translated into specific fields in the Node object on registration.
// Use the node.name or node.spec.providerID field to find the node in the cloud provider.
func (i *Instances) InstanceMetadata(ctx context.Context, node *v1.Node) (*cloudprovider.InstanceMetadata, error) {
	providerID := node.Spec.ProviderID
	instanceID, err := parseInstanceID(providerID)
	if err != nil {
		return nil, err
	}

	instance, err := i.computeService.Get(instanceID)
	if err != nil {
		return nil, err
	}

	instanceFlavor, err := getInstanceFlavor(instance)
	if err != nil {
		return nil, err
	}

	interfaces, err := i.computeService.ListInterfaces(instanceID)
	if err != nil {
		return nil, err
	}

	addresses, err := i.computeService.BuildAddresses(instance, interfaces, i.config.Networking)
	if err != nil {
		return nil, err
	}

	return &cloudprovider.InstanceMetadata{
		ProviderID:    providerID,
		InstanceType:  instanceFlavor,
		NodeAddresses: addresses,
	}, nil
}

func parseInstanceID(providerID string) (string, error) {
	// see https://github.com/kubernetes/kubernetes/issues/85731
	if providerID != "" && !strings.Contains(providerID, "://") {
		providerID = ProviderName + "://" + providerID
	}

	matches := providerIDRegexp.FindStringSubmatch(providerID)
	if len(matches) != 2 {
		return "", fmt.Errorf("ProviderID \"%s\" didn't match expected format \"huaweicloud:///InstanceID\"",
			providerID)
	}
	return matches[1], nil
}

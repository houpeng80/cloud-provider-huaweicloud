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

	"github.com/chnsz/golangsdk"
	"github.com/chnsz/golangsdk/openstack/networking/v1/eips"
	"github.com/chnsz/golangsdk/openstack/vpc/v1/publicips"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"
)

type PublicIpService struct {
	Config *config.Config
}

func (p *PublicIpService) Get(id string) (*publicips.PublicIP, error) {
	client, err := p.getVpcV1Client()
	if err != nil {
		return nil, err
	}

	return publicips.Get(client, id).Extract()
}

func (p *PublicIpService) GetPortId(portID string) ([]publicips.PublicIP, error) {
	client, err := p.getVpcV1Client()
	if err != nil {
		return nil, err
	}

	opts := publicips.ListOpts{
		PortId: portID,
	}
	page, err := publicips.List(client, opts).AllPages()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Error querying EIP by portID %s: %s", portID, err)
	}

	ips, err := publicips.ExtractPublicIPs(page)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "Error extracting EIP data: %s", err)
	}

	return ips, nil
}

func (p *PublicIpService) getVpcV1Client() (*golangsdk.ServiceClient, error) {
	client, err := p.Config.VpcV1Client()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed create VPC V1 client: %s", err))
	}
	return client, nil
}

func (p PublicIpService) UnbindAndDeleteEip(portId, publicIpId string, deleteEip bool) error {
	if len(publicIpId) == 0 {
		return nil
	}
	client, err := p.Config.VpcV1Client()
	if err != nil {
		return err
	}
	updateOpts := eips.UpdateOpts{
		PortID: "",
	}
	unBindEipRes := eips.Update(client, publicIpId, updateOpts)
	if unBindEipRes.Err != nil {
		return status.Errorf(codes.Unavailable,
			"Failed to unBind EIP. Error: %s", unBindEipRes.Err)
	}
	if deleteEip {
		if delEipRes := eips.Delete(client, publicIpId); delEipRes.Err != nil {
			updateOpts.PortID = portId
			if unBindEipRes = eips.Update(client, publicIpId, updateOpts); unBindEipRes.Err != nil {
				return status.Errorf(codes.Internal, "Failed to delete EIP, and failed reBind EIP"+
					"to ELB, please reBind it manually. Error: %s", unBindEipRes.Err)
			}
			return status.Errorf(codes.Unavailable,
				"Failed to delete EIP. Error: %s", delEipRes.Err)
		}
	}
	return nil
}

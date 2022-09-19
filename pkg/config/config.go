/*
Copyright 2020 The Kubernetes Authors.

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

package config

import (
	"fmt"
	"net/http"
	"time"

	"github.com/chnsz/golangsdk"
	"github.com/chnsz/golangsdk/openstack"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/common"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/utils"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/utils/metadata"
)

const (
	UserAgent      = "huaweicloud-kubernetes-ccm"
	defaultTimeout = 60 * time.Second
)

// Config define
type Config struct {
	Global         AuthOpts
	Vpc            VpcOpts
	LoadBalancer   LoadBalancerOpts
	Networking     NetworkingOpts
	Metadata       MetadataOpts
	providerClient *golangsdk.ProviderClient
}

type VpcOpts struct {
	ID string `gcfg:"id"`
}

type AuthOpts struct {
	Cloud     string `gcfg:"cloud"`
	AuthURL   string `gcfg:"auth-url"`
	Region    string `gcfg:"region"`
	AccessKey string `gcfg:"access-key"`
	SecretKey string `gcfg:"secret-key"`
	ProjectID string `gcfg:"project-id"`
}

type LoadBalancerOpts struct {
	NetworkID string `gcfg:"network-id"`
	SubnetID  string `gcfg:"subnet-id"`

	LBMethod   string `gcfg:"lb-method"`
	LBProvider string `gcfg:"lb-provider"`
	FlavorID   string `gcfg:"flavor-id"`
	KeepEIP    bool   `gcfg:"keep-eip"`

	CreateMonitor     bool `gcfg:"create-monitor"`
	MonitorDelay      int  `gcfg:"monitor-delay"`       // Health check interval
	MonitorTimeout    int  `gcfg:"monitor-timeout"`     // Health check timeout
	MonitorMaxRetries int  `gcfg:"monitor-max-retries"` // Health check max retries

	KeepAliveTimeout int `gcfg:"keep-alive-timeout"` // idle timeout, in seconds
	RequestTimeout   int `gcfg:"request-time"`       // request timeout, in seconds
	ResponseTime     int `gcfg:"response-time"`      // response timeout, in seconds
}

func (l LoadBalancerOpts) initDefaultValue() {
	if l.LBProvider == "" {
		l.LBProvider = "vlb"
	}
	if l.LBMethod == "" {
		l.LBMethod = "ROUND_ROBIN"
	}

	if l.MonitorDelay <= 0 {
		l.MonitorDelay = 5
	}
	if l.MonitorTimeout <= 0 {
		l.MonitorTimeout = 3
	}
	if l.MonitorMaxRetries <= 0 {
		l.MonitorMaxRetries = 3
	}

	if l.KeepAliveTimeout <= 0 {
		l.KeepAliveTimeout = int(defaultTimeout.Seconds())
	}
	if l.RequestTimeout <= 0 {
		l.RequestTimeout = int(defaultTimeout.Seconds())
	}
	if l.ResponseTime <= 0 {
		l.ResponseTime = int(defaultTimeout.Seconds())
	}
}

// NetworkingOpts is used for networking settings
type NetworkingOpts struct {
	IPv6SupportDisabled bool     `gcfg:"ipv6-support-disabled"`
	PublicNetworkName   []string `gcfg:"public-network-name"`
	InternalNetworkName []string `gcfg:"internal-network-name"`
}

// MetadataOpts is used for configuring how to talk to metadata service or config drive
type MetadataOpts struct {
	SearchOrder    string            `gcfg:"search-order"`
	RequestTimeout common.MyDuration `gcfg:"request-timeout"`
}

func (m MetadataOpts) initDefaultValue() {
	if m.RequestTimeout == (common.MyDuration{}) {
		m.RequestTimeout.Duration = defaultTimeout
	}
	if m.SearchOrder == "" {
		m.SearchOrder = fmt.Sprintf("%s,%s", metadata.MetadataID, metadata.ConfigDriveID)
	}
}

type serviceCatalog struct {
	Name             string
	Version          string
	Scope            string
	Admin            bool
	ResourceBase     string
	WithOutProjectID bool
}

var allServiceCatalog = map[string]serviceCatalog{
	"ecs": {
		Name:    "ecs",
		Version: "v1",
	},
	"ecsV21": {
		Name:    "ecs",
		Version: "v2.1",
	},
	"evsV1": {
		Name:    "evs",
		Version: "v1",
	},
	"evsV2": {
		Name:    "evs",
		Version: "v2",
	},
	"evsV21": {
		Name:    "evs",
		Version: "v2.1",
	},
	"sfsV2": {
		Name:    "sfs",
		Version: "v2",
	},
	"elbV2": {
		Name:    "elb",
		Version: "v2",
	},
	"vpcV1": {
		Name:    "vpc",
		Version: "v1",
	},
}

func newServiceClient(c *Config, catalogName, region string) (*golangsdk.ServiceClient, error) {
	catalog, ok := allServiceCatalog[catalogName]
	if !ok {
		return nil, fmt.Errorf("service type %s is invalid or not supportted", catalogName)
	}

	client := c.providerClient
	// update ProjectID and region in ProviderClient
	clone := new(golangsdk.ProviderClient)
	*clone = *client
	clone.ProjectID = client.ProjectID
	clone.AKSKAuthOptions.ProjectId = client.ProjectID
	clone.AKSKAuthOptions.Region = region

	sc := &golangsdk.ServiceClient{
		ProviderClient: clone,
	}

	if catalog.Scope == "global" {
		sc.Endpoint = fmt.Sprintf("https://%s.%s/", catalog.Name, c.Global.Cloud)
	} else {
		sc.Endpoint = fmt.Sprintf("https://%s.%s.%s/", catalog.Name, region, c.Global.Cloud)
	}

	sc.ResourceBase = sc.Endpoint
	if catalog.Version != "" {
		sc.ResourceBase = sc.ResourceBase + catalog.Version + "/"
	}
	if !catalog.WithOutProjectID {
		sc.ResourceBase = sc.ResourceBase + client.ProjectID + "/"
	}
	if catalog.ResourceBase != "" {
		sc.ResourceBase = sc.ResourceBase + catalog.ResourceBase + "/"
	}

	return sc, nil
}

func (c *Config) Validate() error {
	err := c.newCloudClient()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) newCloudClient() error {
	ao := golangsdk.AKSKAuthOptions{
		IdentityEndpoint: c.Global.AuthURL,
		AccessKey:        c.Global.AccessKey,
		SecretKey:        c.Global.SecretKey,
		ProjectId:        c.Global.ProjectID,
		ProjectName:      c.Global.Region,
	}

	client, err := openstack.NewClient(ao.IdentityEndpoint)
	if err != nil {
		return err
	}

	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	client.HTTPClient = http.Client{
		Transport: &utils.LogRoundTripper{
			Rt: transport,
		},
	}

	err = openstack.Authenticate(client, ao)
	if err != nil {
		return err
	}

	c.providerClient = client
	c.providerClient.UserAgent.Prepend(UserAgent)
	return nil
}

func (c *Config) SFSV2Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "sfsV2", c.Global.Region)
}

func (c *Config) EcsV1Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "ecs", c.Global.Region)
}

func (c *Config) EcsV21Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "ecsV21", c.Global.Region)
}

func (c *Config) EvsV2Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "evsV2", c.Global.Region)
}

func (c *Config) EvsV21Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "evsV21", c.Global.Region)
}

func (c *Config) EvsV1Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "evsV1", c.Global.Region)
}

func (c *Config) ElbV2Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "elbV2", c.Global.Region)
}

func (c *Config) VpcV1Client() (*golangsdk.ServiceClient, error) {
	return newServiceClient(c, "vpcV1", c.Global.Region)
}

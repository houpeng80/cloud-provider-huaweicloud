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

import "reflect"

type LBMethod string
type Protocol string

const (
	LBMethodRoundRobin       LBMethod = "ROUND_ROBIN"
	LBMethodLeastConnections LBMethod = "LEAST_CONNECTIONS"
	LBMethodSourceIp         LBMethod = "SOURCE_IP"

	ProtocolTCP   Protocol = "TCP"
	ProtocolHTTP  Protocol = "HTTP"
	ProtocolHTTPS Protocol = "HTTPS"
)

type LBService interface {
	Get(ID string) (*LoadBalancer, error)
	GetByName(name string) (*LoadBalancer, error)
	CreateToCompleted(opts *LBCreateOpts) (*LoadBalancer, error)
	Delete(id string) error
	WaitProvisioningStatusActive(id string) (*LoadBalancer, error)
	WaitDeletionCompleted(id string) error

	ListListeners(id string) ([]Listener, error)
	AddListener(opts CreateListenerOpts) (*Listener, error)
	UpdateListener(id string, opts UpdateListenerOpts) error
	DeleteListener(listenerID string) error

	GetPool(loadbalancerID, listenerID string) (*Pool, error)
	CreatePool(opts CreatePoolOpts) (*Pool, error)
	DeletePool(poolID string) error

	ListMembers(poolID string) ([]Member, error)
	AddMember(poolID string, opts CreateMemberOpts) (*Member, error)
	DeleteMember(poolID, memberID string) error
	DeleteAllPoolMembers(poolID string) error

	CreateMonitor(opts CreateMonitorOpts) (*Monitor, error)
	DeleteMonitor(monitorID string) error
}

type LBCreateOpts struct {
	Name        string
	Description string
	Provider    string
	FlavorID    string

	VipNetworkID string
	VipSubnetID  string
	PublicIpId   string
}

type CreateListenerOpts struct {
	Name           string
	Protocol       Protocol
	ProtocolPort   int
	LoadbalancerID string
	ConnLimit      *int

	// The dedicated EBL uses the following fields
	KeepaliveTimeout *int
	ClientTimeout    *int
	MemberTimeout    *int
}

type UpdateListenerOpts struct {
	ConnLimit *int

	// The dedicated EBL uses the following fields
	KeepaliveTimeout *int
	ClientTimeout    *int
	MemberTimeout    *int
}

type CreateMemberOpts struct {
	Name         string
	Address      string
	ProtocolPort int
	SubnetID     string
}

type CreatePoolOpts struct {
	LBMethod       LBMethod
	Protocol       Protocol
	LoadbalancerID string
	ListenerID     string
	Name           string
	Persistence    *SessionPersistence
}

type CreateMonitorOpts struct {
	PoolID        string
	Type          string
	Delay         int
	Timeout       int
	MaxRetries    int
	URLPath       string
	HTTPMethod    string
	ExpectedCodes string
	Name          string
	MonitorPort   int
}

type LoadBalancer struct {
	ID                  string
	Description         string
	AdminStateUp        bool
	TenantID            string
	ProvisioningStatus  string
	VipAddress          string
	VipPortID           string
	VipSubnetID         string
	OperatingStatus     string
	Name                string
	Flavor              string
	Provider            string
	Listeners           []Listener
	Pools               []Pool
	EnterpriseProjectID string
}

type Listener struct {
	ID                     string
	TenantID               string
	ProjectID              string
	Name                   string
	Description            string
	Protocol               string
	ProtocolPort           int
	DefaultPoolID          string
	LoadBalancers          []string
	ConnLimit              int
	Http2Enable            bool
	SniContainerRefs       []string
	CAContainerRef         string
	DefaultTlsContainerRef string
	TlsCiphersPolicy       string
	AdminStateUp           bool
	Pools                  []Pool
	ProvisioningStatus     string

	// The dedicated EBL uses the following fields
	KeepaliveTimeout int
	ClientTimeout    int
	MemberTimeout    int
}

type Pool struct {
	LBMethod           string
	Protocol           string
	Description        string
	Listeners          []string
	Members            []Member
	MonitorID          string
	SubnetID           string
	TenantID           string
	ProjectID          string
	AdminStateUp       bool
	Name               string
	ID                 string
	LoadBalancers      []string
	Persistence        SessionPersistence
	Provider           string
	Monitor            Monitor
	ProvisioningStatus string
}

type SessionPersistence struct {
	Type               string
	CookieName         string
	PersistenceTimeout int
}

type Member struct {
	Name               string
	Weight             int
	AdminStateUp       bool
	TenantID           string
	ProjectID          string
	SubnetID           string
	PoolID             string
	Address            string
	ProtocolPort       int
	ID                 string
	ProvisioningStatus string
	OperatingStatus    string
}

type Monitor struct {
	ID                 string
	Name               string
	TenantID           string
	ProjectID          string
	Type               string
	Delay              int
	Timeout            int
	MaxRetries         int
	HTTPMethod         string
	DomainName         string
	URLPath            string
	ExpectedCodes      string
	AdminStateUp       bool
	MonitorPort        int
	Status             string
	Pools              []string
	ProvisioningStatus string
}

func extractField(arr interface{}, field string) []string {
	array := reflect.ValueOf(arr)
	if array.Len() == 0 {
		return nil
	}
	rst := make([]string, array.Len())
	for i := 0; i < array.Len(); i++ {
		item := array.Index(i)
		if item.Kind() == reflect.Ptr {
			item = item.Elem()
		}

		if item.Kind() == reflect.Struct {
			value := reflect.Indirect(item).FieldByName(field)
			if value.IsValid() {
				rst[i] = value.Interface().(string)
			}
		}
	}
	return rst
}

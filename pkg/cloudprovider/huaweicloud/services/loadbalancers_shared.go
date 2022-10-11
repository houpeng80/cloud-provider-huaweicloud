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
	"github.com/chnsz/golangsdk/openstack/elb/v2/listeners"
	"github.com/chnsz/golangsdk/openstack/elb/v2/loadbalancers"
	"github.com/chnsz/golangsdk/openstack/elb/v2/monitors"
	"github.com/chnsz/golangsdk/openstack/elb/v2/pools"
	"github.com/chnsz/golangsdk/openstack/networking/v1/eips"
	"github.com/chnsz/golangsdk/pagination"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/common"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/utils/multierror"
)

type LBSharedService struct {
	Config *config.Config
}

func (l LBSharedService) Get(id string) (*LoadBalancer, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	instance, err := loadbalancers.Get(client, id).Extract()

	if err != nil {
		if common.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Error, loadbalancer instance %s does not exist", id)
		}
		return nil, status.Errorf(codes.Internal, "Error querying loadbalancer(id:%s) details: %s", id, err)
	}

	return l.buildLoadBalancer(instance), nil
}

// GetByName query the instance matching the name, and return an error if none or more than one is found.
func (l LBSharedService) GetByName(name string) (*LoadBalancer, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	opts := loadbalancers.ListOpts{
		Name: name,
	}
	elbList := make([]loadbalancers.LoadBalancer, 0, 1)
	err = loadbalancers.List(client, opts).EachPage(func(page pagination.Page) (bool, error) {
		list, err := loadbalancers.ExtractLoadBalancers(page)
		if err != nil {
			return false, err
		}
		elbList = append(elbList, list...)

		if len(list) > 1 {
			return false, fmt.Errorf("multiple results where only one expected")
		}
		return true, nil
	})

	if err != nil {
		return nil, status.Errorf(codes.Unknown, "Error querying ELB instances by name: %s", err)
	}

	if len(elbList) == 0 {
		return nil, status.Errorf(codes.NotFound, "Error, not found any ELB instances matched name: %s", name)
	}
	return l.buildLoadBalancer(&elbList[0]), nil
}

// CreateToCompleted : Create a ELB instance and bind the EIP. If it fails, delete the created instances.
func (l LBSharedService) CreateToCompleted(opts *LBCreateOpts) (*LoadBalancer, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	createOpts := loadbalancers.CreateOpts{
		Name:        opts.Name,
		Description: opts.Description,
		Provider:    opts.Provider,

		VipSubnetID: opts.VipSubnetID,
		Flavor:      opts.FlavorID,
	}

	lb, err := loadbalancers.Create(client, createOpts).Extract()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create loadbalancer instance: %s", err)
	}

	loadbalancer, err := l.WaitProvisioningStatusActive(lb.ID)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "Error waiting for loadbalancer to be created: %s", err)
	}

	// associate eip to ELB
	if opts.PublicIpId != "" {
		updateOpts := eips.UpdateOpts{
			PortID: loadbalancer.VipPortID,
		}
		client, err = l.getVpcV1Client()
		if err != nil {
			return nil, err
		}
		r := eips.Update(client, opts.PublicIpId, updateOpts)
		if r.Err != nil {
			err = l.Delete(loadbalancer.ID)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "Failed to bind EIP, and failed to delete "+
					"the created ELB instance, please delete it manually(name: %s). Error: %s", opts.Name, err)
			}
			return nil, status.Errorf(codes.Unavailable,
				"Failed to bind EIP, the created ELB instance is being deleted. Error: %s", err)
		}
	}
	return loadbalancer, nil
}

func (l LBSharedService) WaitProvisioningStatusActive(id string) (*LoadBalancer, error) {
	var instance *LoadBalancer

	err := common.WaitForCompleted(func() (bool, error) {
		lb, err := l.Get(id)
		instance = lb
		if err != nil {
			return false, err
		}

		if instance.ProvisioningStatus == "ACTIVE" {
			return true, nil
		}

		if instance.ProvisioningStatus == "ERROR" {
			return false, status.Error(codes.Unavailable, "LoadBalancer has gone into ERROR provisioning status")
		}

		return false, nil
	})

	return instance, err
}

func (l LBSharedService) Delete(id string) error {
	client, err := l.getElbV2Client()
	if err != nil {
		return err
	}

	err = loadbalancers.Delete(client, id).Err
	if err != nil {
		return status.Errorf(codes.Internal, "Failed to delete loadbalancer: %s", err)
	}

	return l.WaitDeletionCompleted(id)
}

func (l LBSharedService) WaitDeletionCompleted(id string) error {
	return common.WaitForCompleted(func() (bool, error) {
		_, err := l.Get(id)
		if err != nil {
			if common.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	})
}

func (l LBSharedService) ListListeners(id string) ([]Listener, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	opts := listeners.ListOpts{
		LoadbalancerID: id,
	}
	page, err := listeners.List(client, opts).AllPages()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to query a list of ELB listeners %s : %s", id, err)
	}
	arr, err := listeners.ExtractListeners(page)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "Failed to extract ELB listeners %s : %s", id, err)
	}

	return l.buildListeners(arr), nil
}

func (l LBSharedService) AddListener(opts CreateListenerOpts) (*Listener, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	createOpts := listeners.CreateOpts{
		Name:           opts.Name,
		Protocol:       listeners.Protocol(opts.Protocol),
		ProtocolPort:   opts.ProtocolPort,
		LoadbalancerID: opts.LoadbalancerID,
		ConnLimit:      opts.ConnLimit,
	}
	listener, err := listeners.Create(client, createOpts).Extract()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create ELB listener %s : %s", opts.LoadbalancerID, err)
	}

	return l.buildListener(listener), nil
}

func (l LBSharedService) UpdateListener(id string, opts UpdateListenerOpts) error {
	client, err := l.getElbV2Client()
	if err != nil {
		return err
	}

	updateOpts := listeners.UpdateOpts{
		ConnLimit: opts.ConnLimit,
	}
	err = listeners.Update(client, id, updateOpts).Err
	if err != nil {
		return status.Errorf(codes.Internal, "failed to update ELB listener %s : %s", id, err)
	}
	return nil
}

func (l LBSharedService) DeleteListener(listenerID string) error {
	client, err := l.getElbV2Client()
	if err != nil {
		return err
	}
	return listeners.Delete(client, listenerID).Err
}

func (l LBSharedService) GetPool(loadbalancerID, listenerID string) (*Pool, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	opts := pools.ListOpts{
		LoadbalancerID: loadbalancerID,
		ListenerID:     listenerID,
	}
	page, err := pools.List(client, opts).AllPages()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query ELB listener pool: %s", err)
	}

	arr, err := pools.ExtractPools(page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract ELB listener pool: %s", err)
	}

	if len(arr) == 0 {
		return nil, status.Errorf(codes.NotFound, "not found pools")
	}

	return l.buildPool(&arr[0]), nil
}

func (l LBSharedService) CreatePool(opts CreatePoolOpts) (*Pool, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}
	var persistence *pools.SessionPersistence
	if opts.Persistence != nil {
		persistence = &pools.SessionPersistence{
			Type:               opts.Persistence.Type,
			CookieName:         opts.Persistence.CookieName,
			PersistenceTimeout: opts.Persistence.PersistenceTimeout,
		}
	}
	createOpts := pools.CreateOpts{
		LBMethod:       pools.LBMethod(opts.LBMethod),
		Protocol:       pools.Protocol(opts.Protocol),
		LoadbalancerID: opts.LoadbalancerID,
		ListenerID:     opts.ListenerID,
		Name:           opts.Name,
		Persistence:    persistence,
	}

	pool, err := pools.Create(client, createOpts).Extract()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create ELB listener pool: %s", err)
	}
	return l.buildPool(pool), nil
}

func (l LBSharedService) DeletePool(poolID string) error {
	client, err := l.getElbV2Client()
	if err != nil {
		return err
	}

	return pools.Delete(client, poolID).Err
}

func (l LBSharedService) ListMembers(poolID string) ([]Member, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	opts := pools.ListMembersOpts{}
	page, err := pools.ListMembers(client, poolID, opts).AllPages()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to query ELB listener members: %s", err)
	}

	members, err := pools.ExtractMembers(page)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to extract ELB listener members: %s", err)
	}
	return l.buildMembers(members), nil
}

func (l LBSharedService) AddMember(poolID string, opts CreateMemberOpts) (*Member, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}
	createOpts := pools.CreateMemberOpts{
		Address:      opts.Address,
		ProtocolPort: opts.ProtocolPort,
		Name:         opts.Name,
		SubnetID:     opts.SubnetID,
	}
	member, err := pools.CreateMember(client, poolID, createOpts).Extract()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create pool member %s : %s", poolID, err)
	}

	return l.buildMember(member), nil
}

func (l LBSharedService) DeleteMember(poolID, memberID string) error {
	client, err := l.getElbV2Client()
	if err != nil {
		return err
	}
	return pools.DeleteMember(client, poolID, memberID).ExtractErr()
}

func (l LBSharedService) DeleteAllPoolMembers(poolID string) error {
	members, err := l.ListMembers(poolID)
	if err != nil {
		return nil
	}

	mErr := &multierror.Error{}
	for _, m := range members {
		mErr = multierror.Append(mErr, l.DeleteMember(poolID, m.ID))
	}
	if mErr.ErrorOrNil() != nil {
		return status.Errorf(codes.Internal, "failed to clean pool members: %s", mErr)
	}
	return nil
}

func (l LBSharedService) CreateMonitor(opts CreateMonitorOpts) (*Monitor, error) {
	client, err := l.getElbV2Client()
	if err != nil {
		return nil, err
	}

	createOpts := monitors.CreateOpts{
		PoolID:     opts.PoolID,
		Type:       opts.Type,
		Delay:      opts.Delay,
		Timeout:    opts.Timeout,
		MaxRetries: opts.MaxRetries,
		Name:       opts.Name,
	}
	monitor, err := monitors.Create(client, createOpts).Extract()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create pool monitor %s : %s", opts.PoolID, err)
	}

	return l.buildMonitor(monitor), err
}

func (l LBSharedService) DeleteMonitor(id string) error {
	if len(id) == 0 {
		return nil
	}

	client, err := l.getElbV2Client()
	if err != nil {
		return err
	}
	return monitors.Delete(client, id).ExtractErr()
}

func (l LBSharedService) getElbV2Client() (*golangsdk.ServiceClient, error) {
	client, err := l.Config.ElbV2Client()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed create ELB V2 client: %s", err))
	}
	return client, nil
}

func (l LBSharedService) getVpcV1Client() (*golangsdk.ServiceClient, error) {
	client, err := l.Config.VpcV1Client()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed create VPC V1 client: %s", err))
	}
	return client, nil
}

func (l LBSharedService) buildLoadBalancer(lb *loadbalancers.LoadBalancer) *LoadBalancer {
	return &LoadBalancer{
		ID:                  lb.ID,
		Description:         lb.Description,
		AdminStateUp:        lb.AdminStateUp,
		TenantID:            lb.TenantID,
		ProvisioningStatus:  lb.ProvisioningStatus,
		VipAddress:          lb.VipAddress,
		VipPortID:           lb.VipPortID,
		VipSubnetID:         lb.VipSubnetID,
		OperatingStatus:     lb.OperatingStatus,
		Name:                lb.Name,
		Flavor:              lb.Flavor,
		Provider:            lb.Provider,
		Listeners:           l.buildListeners(lb.Listeners),
		Pools:               l.buildPools(lb.Pools),
		EnterpriseProjectID: lb.EnterpriseProjectID,
	}
}

func (l LBSharedService) buildLoadBalancers(arr []loadbalancers.LoadBalancer) []LoadBalancer {
	if len(arr) == 0 {
		return nil
	}
	rst := make([]LoadBalancer, 0, len(arr))
	for pos, lb := range arr {
		instance := l.buildLoadBalancer(&lb)
		rst[pos] = *instance
	}
	return rst
}

func (l LBSharedService) buildLoadBalancerID(arr []listeners.LoadBalancerID) []string {
	if len(arr) == 0 {
		return nil
	}

	lbIDs := make([]string, len(arr), len(arr))
	for pos, lbID := range arr {
		lbIDs[pos] = lbID.ID
	}
	return lbIDs
}

func (l LBSharedService) buildListener(lis *listeners.Listener) *Listener {

	return &Listener{
		ID:                     lis.ID,
		TenantID:               lis.TenantID,
		ProjectID:              lis.ProjectID,
		Name:                   lis.Name,
		Description:            lis.Description,
		Protocol:               lis.Protocol,
		ProtocolPort:           lis.ProtocolPort,
		DefaultPoolID:          lis.DefaultPoolID,
		LoadBalancers:          l.buildLoadBalancerID(lis.Loadbalancers),
		ConnLimit:              lis.ConnLimit,
		Http2Enable:            lis.Http2Enable,
		SniContainerRefs:       lis.SniContainerRefs,
		CAContainerRef:         lis.CAContainerRef,
		DefaultTlsContainerRef: lis.DefaultTlsContainerRef,
		TlsCiphersPolicy:       lis.TlsCiphersPolicy,
		AdminStateUp:           lis.AdminStateUp,
		Pools:                  l.buildPools(lis.Pools),
		ProvisioningStatus:     lis.ProvisioningStatus,
	}
}

func (l LBSharedService) buildListeners(arr []listeners.Listener) []Listener {
	if len(arr) == 0 {
		return nil
	}
	rst := make([]Listener, len(arr), len(arr))
	for pos, listener := range arr {
		lis := l.buildListener(&listener)
		rst[pos] = *lis
	}
	return rst
}

func (l LBSharedService) buildPool(pool *pools.Pool) *Pool {
	return &Pool{
		LBMethod:           pool.LBMethod,
		Protocol:           pool.Protocol,
		Description:        pool.Description,
		Listeners:          extractField(pool.Listeners, "ID"),
		Members:            l.buildMembers(pool.Members),
		MonitorID:          pool.MonitorID,
		SubnetID:           pool.SubnetID,
		TenantID:           pool.TenantID,
		ProjectID:          pool.ProjectID,
		AdminStateUp:       pool.AdminStateUp,
		Name:               pool.Name,
		ID:                 pool.ID,
		LoadBalancers:      extractField(pool.Loadbalancers, "ID"),
		Persistence:        l.buildSessionPersistence(pool.Persistence),
		Provider:           pool.Provider,
		Monitor:            *(l.buildMonitor(&pool.Monitor)),
		ProvisioningStatus: pool.ProvisioningStatus,
	}
}

func (l LBSharedService) buildSessionPersistence(s pools.SessionPersistence) SessionPersistence {
	return SessionPersistence{
		Type:               s.Type,
		CookieName:         s.CookieName,
		PersistenceTimeout: s.PersistenceTimeout,
	}
}

func (l LBSharedService) buildPools(arr []pools.Pool) []Pool {
	if len(arr) == 0 {
		return nil
	}
	rst := make([]Pool, len(arr), len(arr))
	for pos, item := range arr {
		rst[pos] = *(l.buildPool(&item))
	}
	return rst
}

func (l LBSharedService) buildMember(m *pools.Member) *Member {
	return &Member{
		Name:               m.Name,
		Weight:             m.Weight,
		AdminStateUp:       m.AdminStateUp,
		TenantID:           m.TenantID,
		ProjectID:          m.ProjectID,
		SubnetID:           m.SubnetID,
		PoolID:             m.PoolID,
		Address:            m.Address,
		ProtocolPort:       m.ProtocolPort,
		ID:                 m.ID,
		ProvisioningStatus: m.ProvisioningStatus,
		OperatingStatus:    m.OperatingStatus,
	}
}

func (l LBSharedService) buildMembers(arr []pools.Member) []Member {
	if len(arr) == 0 {
		return nil
	}
	rst := make([]Member, len(arr), len(arr))
	for pos, item := range arr {
		rst[pos] = *(l.buildMember(&item))
	}
	return rst
}

func (l LBSharedService) buildMonitor(m *monitors.Monitor) *Monitor {
	return &Monitor{
		ID:                 m.ID,
		Name:               m.Name,
		TenantID:           m.TenantID,
		ProjectID:          m.ProjectID,
		Type:               m.Type,
		Delay:              m.Delay,
		Timeout:            m.Timeout,
		MaxRetries:         m.MaxRetries,
		HTTPMethod:         m.HTTPMethod,
		DomainName:         m.DomainName,
		URLPath:            m.URLPath,
		ExpectedCodes:      m.ExpectedCodes,
		AdminStateUp:       m.AdminStateUp,
		MonitorPort:        m.MonitorPort,
		Status:             m.Status,
		Pools:              extractField(m.Pools, "ID"),
		ProvisioningStatus: m.ProvisioningStatus,
	}
}

func (l LBSharedService) buildMonitors(arr []monitors.Monitor) []Monitor {
	if len(arr) == 0 {
		return nil
	}
	rst := make([]Monitor, 0, len(arr))
	for pos, item := range arr {
		rst[pos] = *(l.buildMonitor(&item))
	}
	return rst
}

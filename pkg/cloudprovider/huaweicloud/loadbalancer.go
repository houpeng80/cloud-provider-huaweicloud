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
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/klog/v2"

	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/cloudprovider/huaweicloud/services"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/common"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"
	"sigs.k8s.io/cloud-provider-huaweicloud/pkg/utils/multierror"
)

const (
	ServiceAnnotationELBClass          = "kubernetes.io/elb.class"
	ServiceAnnotationLBConnectionLimit = "kubernetes.io/connection-limit"
	ServiceAnnotationLBEIPID           = "kubernetes.io/eip-id"
	ServiceAnnotationLBKeepEIP         = "kubernetes.io/keep-eip"
	ServiceAnnotationLBNetworkID       = "kubernetes.io/network-id"
	ServiceAnnotationLBSubnetID        = "kubernetes.io/subnet-id"

	ServiceAnnotationLBProvider = "kubernetes.io/lb-provider"
	ServiceAnnotationLBMethod   = "kubernetes.io/lb-method"

	ServiceAnnotationLBEnableHealthMonitor = "kubernetes.io/enable-health-monitor"
	ServiceAnnotationLBMonitorDelay        = "kubernetes.io/monitor-delay"
	ServiceAnnotationLBMonitorTimeout      = "kubernetes.io/monitor-timeout"
	ServiceAnnotationLBMonitorMaxRetries   = "kubernetes.io/monitor-max-retries"

	ServiceAnnotationLBXForwardedFor = "kubernetes.io/x-forwarded-for"
	ServiceAnnotationLBFlavorID      = "kubernetes.io/flavor-id"

	ServiceAnnotationLBKeepAliveTimeout = "kubernetes.io/keep-alive-timeout"
	ServiceAnnotationLBRequestTimeout   = "kubernetes.io/request-timeout"
	ServiceAnnotationLBResponseTimeout  = "kubernetes.io/response-timeout"
)

type LB struct {
	*HuaweiCloud
	Opts *config.LoadBalancerOpts
}

type serviceParameters struct {
	connectLimit int
	eipID        string
	keepEip      bool
	networkID    string
	subnetID     string

	lBProvider string
	lBMethod   string

	enableHealthMonitor bool
	monitorDelay        int
	monitorTimeout      int
	monitorMaxRetries   int

	keepAliveTimeout int
	requestTimeout   int
	responseTime     int
	flavorID         string
	xForwardedFor    bool
}

type ensureOptions struct {
	context     context.Context
	parameters  *serviceParameters
	lbServices  services.LBService
	clusterName string
	service     *v1.Service
	nodes       []*v1.Node
}

func (l *LB) GetLoadBalancer(ctx context.Context, clusterName string, service *v1.Service) (*v1.LoadBalancerStatus,
	bool, error) {

	loadbalancer, err := l.getLoadBalancerInstance(ctx, clusterName, service)
	if err != nil {
		if common.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	status := &corev1.LoadBalancerStatus{}

	portID := loadbalancer.VipPortID
	if portID != "" {
		ips, err := l.publicIpService.GetPortId(portID)
		if err != nil {
			return nil, false, fmt.Errorf("failed when trying to get floating IP for port %s: %v", portID, err)
		}
		if len(ips) > 0 {
			status.Ingress = []corev1.LoadBalancerIngress{{IP: ips[0].PublicIpAddress}}
		} else {
			status.Ingress = []corev1.LoadBalancerIngress{{IP: loadbalancer.VipAddress}}
		}
	}

	return status, true, nil
}

func (l *LB) getLoadBalancerInstance(ctx context.Context, clusterName string, service *v1.Service) (
	*services.LoadBalancer, error) {
	lbServices, err := l.GetLBService(service)
	if err != nil {
		return nil, err
	}

	name := l.GetLoadBalancerName(ctx, clusterName, service)
	loadbalancer, err := lbServices.GetByName(name)
	if err != nil && common.IsNotFound(err) {
		defaultName := cloudprovider.DefaultLoadBalancerName(service)
		loadbalancer, err = lbServices.GetByName(defaultName)
	}
	if err != nil {
		if common.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "can not find any loadbalancers instance by name")
		}
		return nil, err
	}
	return loadbalancer, nil
}

// GetLoadBalancerName returns the name of the load balancer. Implementations must treat the
// *v1.Service parameter as read-only and not modify it.
func (l *LB) GetLoadBalancerName(ctx context.Context, clusterName string, service *v1.Service) string {
	name := fmt.Sprintf("kube_service_%s_%s_%s", clusterName, service.Namespace, service.Name)
	return cutString(name)
}

// EnsureLoadBalancer creates a new load balancer 'name', or updates the existing one. Returns the status of the balancer
// Implementations must treat the *v1.Service and *v1.Node
// parameters as read-only and not modify them.
// Parameter 'clusterName' is the name of the cluster as presented to kube-controller-manager
func (l *LB) EnsureLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) (
	*v1.LoadBalancerStatus, error) {
	lbServices, err := l.GetLBService(service)
	if err != nil {
		return nil, err
	}

	serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)
	klog.Infof("EnsureLoadBalancer(%s, %s)", clusterName, serviceName)

	if len(nodes) == 0 {
		return nil, fmt.Errorf("there are no available nodes for LoadBalancer service %s", serviceName)
	}

	params, err := l.parseAnnotationParameters(service)
	if err != nil {
		return nil, err
	}

	if len(params.subnetID) == 0 && len(params.networkID) == 0 {
		subnetID, err := getNodeSubnetID(l.HuaweiCloud, *nodes[0])
		if err != nil {
			return nil, status.Errorf(codes.Internal,
				"Failed to find subnet ID from HuaweiCloud and subnet-id not set in config, "+
					"service: %s/%s, error: %v", service.Namespace, service.Name, err)
		}
		params.subnetID = subnetID
	}

	ensureOpts := &ensureOptions{
		context:     ctx,
		parameters:  params,
		lbServices:  lbServices,
		clusterName: clusterName,
		service:     service,
		nodes:       nodes,
	}
	ports := service.Spec.Ports
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports provided to HuaweiCloud load balancer")
	}

	// get exits or create a new ELB instance
	loadbalancer, err := l.getOrCreateLoadbalancer(ensureOpts)
	// query ELB listeners list
	listenerArr, err := lbServices.ListListeners(loadbalancer.ID)
	if err != nil {
		return nil, err
	}

	for portIndex, port := range ports {
		listener := filterListenerByPort(listenerArr, port)

		// add or update listener
		listenerName := cutString(fmt.Sprintf("listener_%d_%s", portIndex, loadbalancer.Name))
		if listener, err = l.addOrUpdateListener(loadbalancer, listener, listenerName, port, ensureOpts); err != nil {
			return nil, err
		}
		listenerArr = popListener(listenerArr, listener.ID)

		// query pool or create pool
		poolName := cutString(fmt.Sprintf("pool_%d_%s", portIndex, loadbalancer.Name))
		pool, err := l.getOrCreatePool(loadbalancer, listener, poolName, ensureOpts)
		if err != nil {
			return nil, err
		}

		// add new members and remove the obsolete members.
		if err = l.addOrRemoveMembers(loadbalancer, port, portIndex, pool, ensureOpts); err != nil {
			return nil, err
		}

		// add or remove health monitor
		monitorName := cutString(fmt.Sprintf("monitor_%d_%s)", portIndex, loadbalancer.Name))
		if err = l.addOrRemoveHealthMonitor(loadbalancer, pool, port, monitorName, ensureOpts); err != nil {
			return nil, err
		}
	}

	// All remaining listeners are obsolete, delete them
	err = l.deleteListeners(loadbalancer, listenerArr, ensureOpts)
	if err != nil {
		return nil, err
	}

	ingressIp := loadbalancer.VipAddress
	if len(params.eipID) != 0 {
		eip, err := l.publicIpService.Get(params.eipID)
		if err != nil {
			return nil, err
		}
		ingressIp = eip.PublicIpAddress
	}

	return &corev1.LoadBalancerStatus{
		Ingress: []corev1.LoadBalancerIngress{{IP: ingressIp}},
	}, nil
}

func (l *LB) getOrCreateLoadbalancer(ensureOpts *ensureOptions) (*services.LoadBalancer, error) {
	clusterName := ensureOpts.clusterName
	service := ensureOpts.service
	params := ensureOpts.parameters
	lbServices := ensureOpts.lbServices

	loadbalancer, err := l.getLoadBalancerInstance(ensureOpts.context, clusterName, service)
	if err != nil && common.IsNotFound(err) {
		opts := &services.LBCreateOpts{
			Name: l.GetLoadBalancerName(ensureOpts.context, clusterName, service),
			Description: fmt.Sprintf("Kubernetes external service %s/%s from cluster %s",
				service.Namespace, service.Name, clusterName),

			Provider:     params.lBProvider,
			FlavorID:     params.flavorID,
			VipNetworkID: params.networkID,
			VipSubnetID:  params.subnetID,
			PublicIpId:   params.eipID,
		}
		loadbalancer, err = lbServices.CreateToCompleted(opts)
	}
	if err != nil {
		return nil, err
	}
	return loadbalancer, nil
}

func (l *LB) addOrRemoveHealthMonitor(loadbalancer *services.LoadBalancer,
	pool *services.Pool, port v1.ServicePort, monitorName string, ensureOpts *ensureOptions) error {

	lbServices := ensureOpts.lbServices
	params := ensureOpts.parameters

	monitorID := pool.MonitorID
	if monitorID == "" && params.enableHealthMonitor {
		klog.V(4).Infof("Creating monitor for pool %s", pool.ID)

		monitor, err := l.createHealthMonitor(monitorName, pool.ID, port, params, lbServices)
		if err != nil {
			return fmt.Errorf("error creating LB pool health monitor: %v", err)
		}
		monitorID = monitor.ID

		loadbalancer, err = lbServices.WaitProvisioningStatusActive(loadbalancer.ID)
		if err != nil {
			return fmt.Errorf("timeout when waiting for loadbalancer to be ACTIVE after creating member, "+
				"current provisioning status %s", loadbalancer.ProvisioningStatus)
		}
	} else if monitorID != "" && !params.enableHealthMonitor {
		klog.Infof("Deleting health monitor %s for pool %s", monitorID, pool.ID)
		err := lbServices.DeleteMonitor(monitorID)
		if err != nil {
			return fmt.Errorf("failed to delete health monitor %s for pool %s, error: %v",
				monitorID, pool.ID, err)
		}
	}
	return nil
}

func (l *LB) createHealthMonitor(name, poolID string,
	port v1.ServicePort, params *serviceParameters, lbServices services.LBService) (*services.Monitor, error) {

	monitorProtocol := string(port.Protocol)
	if port.Protocol == corev1.ProtocolUDP {
		monitorProtocol = "UDP-CONNECT"
	}

	opts := services.CreateMonitorOpts{
		Name:       name,
		PoolID:     poolID,
		Type:       monitorProtocol,
		Delay:      params.monitorDelay,
		Timeout:    params.monitorTimeout,
		MaxRetries: params.monitorMaxRetries,
	}

	monitor, err := lbServices.CreateMonitor(opts)
	if err != nil {
		return nil, fmt.Errorf("error creating LB pool health monitor: %v", err)
	}

	return monitor, nil
}

func (l *LB) addOrRemoveMembers(loadbalancer *services.LoadBalancer,
	port v1.ServicePort, portIndex int, pool *services.Pool, ensureOpts *ensureOptions) error {

	params := ensureOpts.parameters
	nodes := ensureOpts.nodes
	lbServices := ensureOpts.lbServices

	members, err := lbServices.ListMembers(pool.ID)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		address, err := getNodeAddress(node)
		if err != nil {
			if common.IsNotFound(err) {
				// Node failure, do not create member
				klog.Warningf("Failed to create LB pool member for node %s: %v", node.Name, err)
				continue
			} else {
				return fmt.Errorf("error getting address for node %s: %v", node.Name, err)
			}
		}

		if !isMemberExists(members, address, int(port.NodePort)) {
			klog.V(4).Infof("Creating member for pool %s", pool.ID)
			opts := services.CreateMemberOpts{
				Name:         cutString(fmt.Sprintf("member_%s_%d_%s", loadbalancer.Name, portIndex, node.Name)),
				ProtocolPort: int(port.NodePort),
				Address:      address,
				SubnetID:     params.subnetID,
			}
			_, err = lbServices.AddMember(pool.ID, opts)
			if err != nil {
				return fmt.Errorf("error creating LB pool member for node: %s, %v", node.Name, err)
			}

			loadbalancer, err = lbServices.WaitProvisioningStatusActive(loadbalancer.ID)
			if err != nil {
				return fmt.Errorf("timeout when waiting for loadbalancer to be ACTIVE after creating member, "+
					"current provisioning status %s", loadbalancer.ProvisioningStatus)
			}
		} else {
			members = popMember(members, address, int(port.NodePort))
		}
		klog.V(4).Infof("Ensured pool %s has member for %s at %s", pool.ID, node.Name, address)
	}

	// delete the remaining elements in members
	for _, member := range members {
		err = l.deleteMember(loadbalancer, pool.ID, member, ensureOpts)
		if err != nil {
			return err
		}
	}

	return nil
}

func (l *LB) deleteMember(loadbalancer *services.LoadBalancer,
	poolID string, member services.Member, ensureOpts *ensureOptions) error {
	lbServices := ensureOpts.lbServices

	klog.V(4).Infof("Deleting obsolete member %s for pool %s address %s", member.ID, poolID)
	err := lbServices.DeleteMember(poolID, member.ID)
	if err != nil && !common.IsNotFound(err) {
		return fmt.Errorf("error deleting obsolete member %s for pool %s address %s: %v",
			poolID, member.ID, member.Address, err)
	}

	loadbalancer, err = lbServices.WaitProvisioningStatusActive(loadbalancer.ID)
	if err != nil {
		return fmt.Errorf("timeout when waiting for loadbalancer to be ACTIVE after creating member, "+
			"current provisioning status %s", loadbalancer.ProvisioningStatus)
	}
	return nil
}

func isMemberExists(members []services.Member, addr string, port int) bool {
	for _, member := range members {
		if member.Address == addr && member.ProtocolPort == port {
			return true
		}
	}

	return false
}

func (l *LB) getOrCreatePool(loadbalancer *services.LoadBalancer,
	listener *services.Listener, poolName string, ensureOpts *ensureOptions) (*services.Pool, error) {

	pool, err := ensureOpts.lbServices.GetPool(loadbalancer.ID, listener.ID)
	if err != nil && common.IsNotFound(err) {
		if pool, err = l.createPool(poolName, listener, ensureOpts); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return pool, nil
}

func (l *LB) createPool(name string, listener *services.Listener, ensureOpts *ensureOptions) (*services.Pool, error) {
	params := ensureOpts.parameters
	affinity := ensureOpts.service.Spec.SessionAffinity
	lbServices := ensureOpts.lbServices

	if len(params.lBMethod) == 0 {
		return nil, fmt.Errorf("loadbalance method is empty")
	}
	var persistence *services.SessionPersistence
	switch affinity {
	case corev1.ServiceAffinityNone:
		persistence = nil
	case corev1.ServiceAffinityClientIP:
		persistence = &services.SessionPersistence{Type: "SOURCE_IP"}
	default:
		return nil, fmt.Errorf("unsupported load balancer affinity: %v", affinity)
	}

	opts := services.CreatePoolOpts{
		Name:        name,
		ListenerID:  listener.ID,
		LBMethod:    services.LBMethod(params.lBMethod),
		Protocol:    services.Protocol(listener.Protocol),
		Persistence: persistence,
	}
	return lbServices.CreatePool(opts)
}

func popMember(members []services.Member, addr string, port int) []services.Member {
	for i, m := range members {
		if m.Address == addr && m.ProtocolPort == port {
			members[i] = members[len(members)-1]
			members = members[:len(members)-1]
		}
	}
	return members
}

func popListener(arr []services.Listener, id string) []services.Listener {
	for i, lis := range arr {
		if lis.ID == id {
			arr[i] = arr[len(arr)-1]
			arr = arr[:len(arr)-1]
			break
		}
	}
	return arr
}

func (l *LB) deleteListeners(loadbalancer *services.LoadBalancer, arr []services.Listener, opts *ensureOptions) error {
	lbServices := opts.lbServices

	mErr := &multierror.Error{}
	for _, lis := range arr {
		pool, err := lbServices.GetPool(loadbalancer.ID, lis.ID)
		if err != nil && !common.IsNotFound(err) {
			mErr = multierror.Append(mErr, err)
			continue
		}
		if err == nil {
			l.deletePool(lbServices, pool, mErr)
		}
		// delete ELB listener
		if err = lbServices.DeleteListener(lis.ID); err != nil && !common.IsNotFound(err) {
			mErr = multierror.Append(mErr, fmt.Errorf("failed to delete ELB listener %s : %s ", lis.ID, err))
		}
	}

	if mErr.ErrorOrNil() != nil {
		return fmt.Errorf("failed to delete listeners: %s", mErr)
	}

	return nil
}

func (l *LB) deletePool(lbServices services.LBService, pool *services.Pool, mErr *multierror.Error) {
	// delete all members of pool
	if err := lbServices.DeleteAllPoolMembers(pool.ID); err != nil {
		mErr = multierror.Append(mErr, err)
	}
	// delete the pool monitor if exists
	if err := lbServices.DeleteMonitor(pool.MonitorID); err != nil && !common.IsNotFound(err) {
		mErr = multierror.Append(mErr, err)
	}
	// delete ELB listener pool
	if err := lbServices.DeletePool(pool.ID); err != nil && !common.IsNotFound(err) {
		mErr = multierror.Append(mErr, err)
	}
}

func (l *LB) addOrUpdateListener(loadbalancer *services.LoadBalancer, listener *services.Listener,
	listenerName string, port v1.ServicePort, ensureOpts *ensureOptions) (*services.Listener, error) {

	params := ensureOpts.parameters
	lbServices := ensureOpts.lbServices

	if listener == nil {
		opts := services.CreateListenerOpts{
			Name:           listenerName,
			Protocol:       services.Protocol(port.Protocol),
			ProtocolPort:   int(port.Port),
			LoadbalancerID: loadbalancer.ID,
			ConnLimit:      &params.connectLimit,

			KeepaliveTimeout: &params.keepAliveTimeout,
			ClientTimeout:    &params.requestTimeout,
			MemberTimeout:    &params.responseTime,
		}
		addListener, err := lbServices.AddListener(opts)
		listener = addListener
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Failed to create listener for loadbalancer %s: %v",
				loadbalancer.ID, err)
		}
	} else {
		// update listener if ConnLimit changed
		hasChanged := false
		updateOpts := services.UpdateListenerOpts{}

		if params.connectLimit != listener.ConnLimit {
			updateOpts.ConnLimit = &params.connectLimit
			hasChanged = true
		}
		if params.keepAliveTimeout != listener.KeepaliveTimeout {
			updateOpts.KeepaliveTimeout = &params.keepAliveTimeout
			hasChanged = true
		}
		if params.requestTimeout != listener.ClientTimeout {
			updateOpts.ClientTimeout = &params.requestTimeout
			hasChanged = true
		}
		if params.responseTime != listener.MemberTimeout {
			updateOpts.MemberTimeout = &params.responseTime
			hasChanged = true
		}

		if hasChanged {
			if err := lbServices.UpdateListener(listener.ID, updateOpts); err != nil {
				return nil, err
			}
		}
		klog.Infof("Listener %s updated for loadbalancer %s", listener.ID, loadbalancer.ID)
	}
	return listener, nil
}

func filterListenerByPort(listenerArr []services.Listener, port v1.ServicePort) *services.Listener {
	for _, l := range listenerArr {
		if services.Protocol(l.Protocol) == parseListenerProtocol(port.Protocol) && l.ProtocolPort == int(port.Port) {
			return &l
		}
	}

	return nil
}

func parseListenerProtocol(protocol corev1.Protocol) services.Protocol {
	switch protocol {
	case corev1.ProtocolTCP:
		return services.ProtocolTCP
	default:
		return services.Protocol(protocol)
	}
}

func (l *LB) parseAnnotationParameters(service *v1.Service) (*serviceParameters, error) {
	params := serviceParameters{}

	str := getStringFromSvsAnnotation(service, ServiceAnnotationLBConnectionLimit, "")
	connectLimit, err := strconv.Atoi(str)
	if err != nil {
		klog.Warningf("Could not parse int value from '%s' error '%s', failing back to default", str, err)
		connectLimit = -1
	}
	params.connectLimit = connectLimit

	params.eipID = getStringFromSvsAnnotation(service, ServiceAnnotationLBEIPID, "")
	params.keepEip, err = getBoolFromSvsAnnotation(service, ServiceAnnotationLBKeepEIP, l.Opts.KeepEIP)
	if err != nil {
		return nil, err
	}
	params.networkID = getStringFromSvsAnnotation(service, ServiceAnnotationLBNetworkID, l.Opts.NetworkID)
	params.subnetID = getStringFromSvsAnnotation(service, ServiceAnnotationLBSubnetID, l.Opts.SubnetID)

	params.lBProvider = getStringFromSvsAnnotation(service, ServiceAnnotationLBProvider, l.Opts.LBProvider)
	params.lBMethod = getStringFromSvsAnnotation(service, ServiceAnnotationLBMethod, l.Opts.LBMethod)

	params.enableHealthMonitor, err = getBoolFromSvsAnnotation(service, ServiceAnnotationLBEnableHealthMonitor,
		l.Opts.CreateMonitor)
	if err != nil {
		klog.Warningf("Could not parse bool value from '%s' error '%s', failing back to default", str, err)
	}

	params.monitorDelay = getIntFromSvsAnnotation(service, ServiceAnnotationLBMonitorDelay, l.Opts.MonitorDelay)
	params.monitorTimeout = getIntFromSvsAnnotation(service, ServiceAnnotationLBMonitorTimeout, l.Opts.MonitorTimeout)
	params.monitorMaxRetries = getIntFromSvsAnnotation(service, ServiceAnnotationLBMonitorMaxRetries,
		l.Opts.MonitorMaxRetries)

	params.xForwardedFor, err = getBoolFromSvsAnnotation(service, ServiceAnnotationLBXForwardedFor, false)
	params.flavorID = getStringFromSvsAnnotation(service, ServiceAnnotationLBFlavorID, l.Opts.FlavorID)

	params.keepAliveTimeout = getIntFromSvsAnnotation(service, ServiceAnnotationLBKeepAliveTimeout,
		l.Opts.KeepAliveTimeout)
	params.requestTimeout = getIntFromSvsAnnotation(service, ServiceAnnotationLBRequestTimeout,
		l.Opts.RequestTimeout)
	params.responseTime = getIntFromSvsAnnotation(service, ServiceAnnotationLBResponseTimeout,
		l.Opts.ResponseTime)

	return &params, nil
}

func getNodeSubnetID(hc *HuaweiCloud, node corev1.Node) (string, error) {
	ipAddress, err := getNodeAddress(&node)
	if err != nil {
		return "", err
	}

	instance, err := hc.computeService.GetByName(node.Name)
	if err != nil {
		return "", err
	}

	interfaces, err := hc.computeService.ListInterfaces(instance.ID)
	if err != nil {
		return "", err
	}

	for _, intfs := range interfaces {
		for _, fixedIP := range intfs.FixedIPs {
			if fixedIP.IPAddress == ipAddress {
				return fixedIP.SubnetID, nil
			}
		}
	}

	return "", fmt.Errorf("failed to get node subnet ID")
}

func getNodeAddress(node *corev1.Node) (string, error) {
	addresses := node.Status.Addresses
	if len(addresses) == 0 {
		return "", status.Errorf(codes.NotFound, "error, current node do not have addresses, nodeName: %s",
			node.Name)
	}

	allowedIPTypes := []corev1.NodeAddressType{corev1.NodeInternalIP, corev1.NodeExternalIP}
	for _, ipType := range allowedIPTypes {
		for _, addr := range addresses {
			if addr.Type == ipType {
				return addr.Address, nil
			}
		}
	}
	return "", status.Errorf(codes.NotFound, "error, current node do not have any valid addresses, nodeName: %s",
		node.Name)
}

// UpdateLoadBalancer updates hosts under the specified load balancer.
// Implementations must treat the *v1.Service and *v1.Node
// parameters as read-only and not modify them.
// Parameter 'clusterName' is the name of the cluster as presented to kube-controller-manager
func (l *LB) UpdateLoadBalancer(ctx context.Context, clusterName string, service *v1.Service, nodes []*v1.Node) error {
	return nil
}

// EnsureLoadBalancerDeleted deletes the specified load balancer if it
// exists, returning nil if the load balancer specified either didn't exist or
// was successfully deleted.
// This construction is useful because many cloud providers' load balancers
// have multiple underlying components, meaning a Get could say that the LB
// doesn't exist even if some part of it is still laying around.
// Implementations must treat the *v1.Service parameter as read-only and not modify it.
// Parameter 'clusterName' is the name of the cluster as presented to kube-controller-manager
func (l *LB) EnsureLoadBalancerDeleted(ctx context.Context, clusterName string, service *v1.Service) error {
	serviceName := fmt.Sprintf("%s/%s", service.Namespace, service.Name)
	klog.Infof("EnsureLoadBalancerDeleted(%s, %s)", clusterName, serviceName)

	params, err := l.parseAnnotationParameters(service)
	if err != nil {
		return err
	}
	if params.keepEip && len(params.eipID) == 0 {
		return fmt.Errorf("there are no available nodes for LoadBalancer service %s", serviceName)
	}
	loadBalancer, err := l.getLoadBalancerInstance(ctx, clusterName, service)
	if err != nil {
		if common.IsNotFound(err) {
			return nil
		}
		return err
	}
	lbService, err := l.GetLBService(service)
	if err != nil {
		return err
	}
	// query ELB listeners list
	listenerArr, err := lbService.ListListeners(loadBalancer.ID)
	if err != nil {
		return err
	}
	if err = l.deleteListeners(loadBalancer, listenerArr, &ensureOptions{lbServices: lbService}); err != nil {
		return err
	}
	if err = l.publicIpService.UnbindAndDeleteEip(loadBalancer.VipPortID, params.eipID, params.keepEip); err != nil {
		return err
	}
	if err = lbService.Delete(loadBalancer.ID); err != nil {
		return err
	}
	return nil
}

// cutString makes sure the string length doesn't exceed 255, which is usually the maximum string length in HuaweiCloud.
func cutString(original string) string {
	ret := original
	if len(original) > 255 {
		ret = original[:255]
	}
	return ret
}

func getStringFromSvsAnnotation(service *corev1.Service, annotationKey string, defaultSetting string) string {
	if annotationValue, ok := service.Annotations[annotationKey]; ok {
		klog.V(4).Infof("Found a Service Annotation: %v = %v", annotationKey, annotationValue)
		return annotationValue
	}
	klog.V(4).Infof("Could not find a Service Annotation; falling back on cloud-config setting: %v = %v",
		annotationKey, defaultSetting)
	return defaultSetting
}

func getIntFromSvsAnnotation(service *corev1.Service, annotationKey string, defaultSetting int) int {
	if annotationValue, ok := service.Annotations[annotationKey]; ok {
		returnValue, err := strconv.Atoi(annotationValue)
		if err != nil {
			klog.Warningf("Could not parse int value from %q, failing back to default %s = %v, %v",
				annotationValue, annotationKey, defaultSetting, err)
			return defaultSetting
		}

		klog.V(4).Infof("Found a Service Annotation: %v = %v", annotationKey, annotationValue)
		return returnValue
	}

	klog.V(4).Infof("Could not find a Service Annotation; falling back to default setting: %v = %v",
		annotationKey, defaultSetting)
	return defaultSetting
}

func getBoolFromSvsAnnotation(service *corev1.Service, annotationKey string, defaultSetting bool) (bool, error) {
	if annotationValue, ok := service.Annotations[annotationKey]; ok {
		returnValue := false
		switch annotationValue {
		case "true":
			returnValue = true
		case "false":
			returnValue = false
		default:
			return returnValue, fmt.Errorf("unknown %s annotation: %v, specify \"true\" or \"false\" ",
				annotationKey, annotationValue)
		}

		klog.V(4).Infof("Found a Service Annotation: %v = %v", annotationKey, returnValue)
		return returnValue, nil
	}
	klog.V(4).Infof("Could not find a Service Annotation; falling back to default setting: %v = %v",
		annotationKey, defaultSetting)
	return defaultSetting, nil
}

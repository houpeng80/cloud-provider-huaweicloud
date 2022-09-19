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

import "sigs.k8s.io/cloud-provider-huaweicloud/pkg/config"

type LBDedicatedService struct {
	Config *config.Config
}

func (l LBDedicatedService) Get(ID string) (*LoadBalancer, error) {
	return nil, nil
}

func (l LBDedicatedService) GetByName(name string) (*LoadBalancer, error) {
	return nil, nil
}

func (l LBDedicatedService) CreateToCompleted(opts *LBCreateOpts) (*LoadBalancer, error) {
	return nil, nil
}

func (l LBDedicatedService) Delete(id string) error {
	return nil
}

func (l LBDedicatedService) WaitProvisioningStatusActive(id string) (*LoadBalancer, error) {
	return nil, nil
}

func (l LBDedicatedService) WaitDeletionCompleted(id string) error {
	return nil
}

func (l LBDedicatedService) ListListeners(id string) ([]Listener, error) {
	return nil, nil
}

func (l LBDedicatedService) AddListener(opts CreateListenerOpts) (*Listener, error) {
	return nil, nil
}

func (l LBDedicatedService) UpdateListener(id string, opts UpdateListenerOpts) error {
	return nil
}

func (l LBDedicatedService) DeleteListener(listenerID string) error {
	return nil
}

func (l LBDedicatedService) GetPool(loadbalancerID, listenerID string) (*Pool, error) {
	return nil, nil
}

func (l LBDedicatedService) CreatePool(opts CreatePoolOpts) (*Pool, error) {
	return nil, nil
}

func (l LBDedicatedService) DeletePool(poolID string) error {
	return nil
}

func (l LBDedicatedService) ListMembers(poolID string) ([]Member, error) {
	return nil, nil
}

func (l LBDedicatedService) AddMember(poolID string, opts CreateMemberOpts) (*Member, error) {
	return nil, nil
}
func (l LBDedicatedService) DeleteMember(poolID, memberID string) error {
	return nil
}

func (l LBDedicatedService) DeleteAllPoolMembers(poolID string) error {
	return nil
}

func (l LBDedicatedService) CreateMonitor(opts CreateMonitorOpts) (*Monitor, error) {
	return nil, nil
}

func (l LBDedicatedService) DeleteMonitor(monitorID string) error {
	return nil
}

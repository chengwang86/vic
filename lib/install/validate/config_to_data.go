// Copyright 2017 VMware, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validate

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-units"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"github.com/vmware/vic/lib/config"
	"github.com/vmware/vic/lib/config/executor"
	"github.com/vmware/vic/lib/install/data"
	"github.com/vmware/vic/pkg/vsphere/vm"
)

const (
	httpProxy  = "HTTP_PROXY"
	httpsProxy = "HTTPS_PROXY"
)

// Finder is defined for easy to test
type Finder interface {
	ObjectReference(ctx context.Context, ref types.ManagedObjectReference) (object.Reference, error)
}

// SetDataFromVM set value based on VCH VM properties
func SetDataFromVM(ctx context.Context, finder Finder, vm *vm.VirtualMachine, d *data.Data) error {
	// display name
	name, err := vm.Name(ctx)
	if err != nil {
		return err
	}
	d.DisplayName = name

	// compute resource
	parent, err := vm.ResourcePool(ctx)
	if err != nil {
		return err
	}
	var mrp mo.ResourcePool
	if err = parent.Properties(ctx, parent.Reference(), []string{"parent"}, &mrp); err != nil {
		return err
	}

	if mrp.Parent == nil {
		return fmt.Errorf("Failed to get parent resource pool")
	}
	or, err := finder.ObjectReference(ctx, *mrp.Parent)
	if err != nil {
		return err
	}
	rp, ok := or.(*object.ResourcePool)
	if !ok {
		return fmt.Errorf("parent resource %s is not resource pool", mrp.Parent)
	}
	d.ComputeResourcePath = rp.InventoryPath

	// TODO: set VCH resource limits and VCH endpoint VM resource limits
	return nil
}

// NewDataFromConfig converts VirtualContainerHostConfigSpec back to data.Data object
// This method does not touch any configuration for VCH VM or resource pool, which should be retrieved from VM or vApp attributes
func NewDataFromConfig(ctx context.Context, finder Finder, conf *config.VirtualContainerHostConfigSpec) (d *data.Data, err error) {
	if conf == nil {
		return
	}

	d = data.NewData()
	if d.Target.URL, err = url.Parse(conf.Connection.Target); err != nil {
		return
	}
	d.OpsUser = conf.Connection.Username
	d.OpsPassword = &conf.Connection.Token
	d.Thumbprint = conf.Connection.TargetThumbprint

	d.AsymmetricRouting = conf.AsymmetricRouting

	if err = setBridgeNetwork(ctx, finder, d, conf); err != nil {
		return
	}

	if conf.Certificate.HostCertificate != nil {
		d.CertPEM = conf.Certificate.HostCertificate.Cert
		d.KeyPEM = conf.Certificate.HostCertificate.Key
	}
	d.ClientCAs = conf.Certificate.CertificateAuthorities
	d.RegistryCAs = conf.RegistryCertificateAuthorities

	clientNet, err := getNetworkConfig(ctx, finder, conf.ExecutorConfig.Networks[config.ClientNetworkName])
	if err != nil {
		return
	}
	d.ClientNetwork = *clientNet
	publicNet, err := getNetworkConfig(ctx, finder, conf.ExecutorConfig.Networks[config.PublicNetworkName])
	if err != nil {
		return
	}
	d.PublicNetwork = *publicNet
	mgmtNet, err := getNetworkConfig(ctx, finder, conf.ExecutorConfig.Networks[config.ManagementNetworkName])
	if err != nil {
		return
	}
	d.ManagementNetwork = *mgmtNet

	// remove duplicate network config
	if d.ManagementNetwork.Name == d.ClientNetwork.Name {
		d.ManagementNetwork = data.NetworkConfig{}
	}
	if d.ClientNetwork.Name == d.PublicNetwork.Name {
		// revert client network settings
		d.ClientNetwork = data.NetworkConfig{}
	}

	if err = setContainerNetworks(ctx, finder, d, conf.Network.ContainerNetworks, conf.BridgeNetwork); err != nil {
		return
	}

	d.Debug.Debug = conf.Diagnostics.DebugLevel
	if conf.ExecutorConfig.Networks[config.PublicNetworkName] != nil {
		d.DNS = conf.ExecutorConfig.Networks[config.PublicNetworkName].Network.Nameservers
	}

	if err = setHTTPProxies(d, conf); err != nil {
		return
	}

	if err = setImageStore(d, conf); err != nil {
		return
	}
	setVolumeLocations(d, conf)
	d.InsecureRegistries = conf.InsecureRegistries
	if d.ScratchSize, err = getHumanSize(conf.ScratchSize, "KB"); err != nil {
		return
	}
	if conf.Diagnostics.SysLogConfig != nil {
		if d.SyslogConfig.Addr, err = url.Parse(fmt.Sprintf("%s://%s", conf.Diagnostics.SysLogConfig.Network, conf.Diagnostics.SysLogConfig.RAddr)); err != nil {
			return
		}
	}
	return
}

func getHumanSize(size int64, unit string) (string, error) {
	is, err := units.FromHumanSize(fmt.Sprintf("%d%s", size, unit))
	if err != nil {
		return "", err
	}
	hsize := units.HumanSize(float64(is))
	hsize = strings.Replace(hsize, " ", "", -1)
	return hsize, nil
}

func setImageStore(d *data.Data, conf *config.VirtualContainerHostConfigSpec) error {
	if len(conf.ImageStores) != 1 {
		return fmt.Errorf("no image store or multiple image store configured")
	}
	imageURL := conf.ImageStores[0]
	if imageURL.Path != "" {
		path := strings.Split(imageURL.Path, "/")
		if len(path) > 1 && path[len(path)-1] != "" {
			imageURL.Path = strings.Join(path[:len(path)-1], "/")
		}
		if imageURL.Scheme != "" && len(path) == 1 {
			imageURL.Path = ""
		}
	}
	d.ImageDatastorePath = urlString(imageURL)
	return nil
}

func setVolumeLocations(d *data.Data, conf *config.VirtualContainerHostConfigSpec) {
	d.VolumeLocations = make(map[string]*url.URL, len(conf.VolumeLocations))

	var dsURL object.DatastorePath
	for k, v := range conf.VolumeLocations {
		if ok := dsURL.FromString(v.Path); !ok {
			log.Debugf("%s is not datastore path", v.Path)
			d.VolumeLocations[k] = v
			continue
		}
		u := *v
		u.Path = dsURL.Path
		d.VolumeLocations[k] = &u
	}
}

func urlString(u url.URL) string {
	if u.Scheme == "" {
		if u.Path == "" {
			return u.Host
		}
		return fmt.Sprintf("%s/%s", u.Host, u.Path)
	}
	return u.String()
}

func setHTTPProxies(d *data.Data, conf *config.VirtualContainerHostConfigSpec) error {
	persona := conf.Sessions[config.PublicNetworkName]
	if persona == nil {
		return nil
	}
	for _, env := range persona.Cmd.Env {
		if !strings.HasPrefix(env, httpProxy) && !strings.HasPrefix(env, httpsProxy) {
			continue
		}

		strs := strings.Split(env, "=")
		if len(strs) != 2 {
			return fmt.Errorf("wrong env format: %s", env)
		}
		url, err := url.Parse(strs[1])
		if err != nil {
			return err
		}
		if strs[0] == httpProxy {
			d.HTTPProxy = url
		} else {
			d.HTTPSProxy = url
		}
	}
	return nil
}

func setContainerNetworks(ctx context.Context, finder Finder, d *data.Data, containerNetworks map[string]*executor.ContainerNetwork, bridge string) error {
	for k, v := range containerNetworks {
		if k == bridge {
			// bridge network is persisted in executor network as well, skip it here
			continue
		}
		name, err := getNameFromID(ctx, finder, v.Common.ID)
		if err != nil {
			return err
		}
		d.ContainerNetworks.MappedNetworks[k] = name
		d.ContainerNetworks.MappedNetworksGateways[k] = v.Gateway
		d.ContainerNetworks.MappedNetworksDNS[k] = v.Nameservers
		d.ContainerNetworks.MappedNetworksIPRanges[k] = v.Pools
	}
	return nil
}

func getNetworkConfig(ctx context.Context, finder Finder, conf *executor.NetworkEndpoint) (net *data.NetworkConfig, err error) {
	net = &data.NetworkConfig{}
	if conf == nil {
		return
	}
	if net.Name, err = getNameFromID(ctx, finder, conf.Network.ID); err != nil {
		return
	}
	net.Destinations = conf.Network.Destinations
	net.Gateway = conf.Network.Gateway
	if conf.IP != nil {
		net.IP = *conf.IP
	}
	return
}

func setBridgeNetwork(ctx context.Context, finder Finder, d *data.Data, conf *config.VirtualContainerHostConfigSpec) error {
	bridgeNet := conf.ExecutorConfig.Networks[conf.Network.BridgeNetwork]
	name, err := getNameFromID(ctx, finder, bridgeNet.Network.ID)
	if err != nil {
		return err
	}
	d.BridgeNetworkName = name
	d.BridgeIPRange = conf.Network.BridgeIPRange

	return nil
}

func getNameFromID(ctx context.Context, finder Finder, mobID string) (string, error) {
	moref := new(types.ManagedObjectReference)
	ok := moref.FromString(mobID)
	if !ok {
		return "", fmt.Errorf("could not restore serialized managed object reference: %s", mobID)
	}

	if finder == nil {
		return "", fmt.Errorf("finder is not set")
	}

	obj, err := finder.ObjectReference(ctx, *moref)
	if err != nil {
		return "", err
	}
	type common interface {
		ObjectName(ctx context.Context) (string, error)
	}
	name, err := obj.(common).ObjectName(ctx)
	if err != nil {
		return "", err
	}
	log.Debugf("%s name: %s", mobID, name)
	return name, nil
}

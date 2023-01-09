//go:build !framework
// +build !framework

package sdk

import (
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
)

var _ ResourceData = &PluginSdkResourceData{}

type PluginSdkResourceData struct {
	resourceData *pluginsdk.ResourceData
}

// IsNewResource TODO Remove this
func (p *PluginSdkResourceData) IsNewResource() bool {
	return p.resourceData.IsNewResource()
}

func (p *PluginSdkResourceData) GetOk(key string) (interface{}, bool) {
	return p.resourceData.GetOk(key)
}

func (p *PluginSdkResourceData) GetOkExists(key string) (interface{}, bool) {
	return p.resourceData.GetOkExists(key)
}

func (p *PluginSdkResourceData) GetChange(key string) (interface{}, interface{}) {
	return p.resourceData.GetChange(key)
}

func NewPluginSdkResourceData(d *pluginsdk.ResourceData) *PluginSdkResourceData {
	return &PluginSdkResourceData{
		resourceData: d,
	}
}

// Get returns a value from either the config/state depending on where this is called
// in Create and Update functions this will return from the config
// in Read, Exists and Import functions this will return from the state
// NOTE: this should not be called from Delete functions.
func (p *PluginSdkResourceData) Get(key string) interface{} {
	return p.resourceData.Get(key)
}

func (p *PluginSdkResourceData) GetFromConfig(key string) interface{} {
	// p.resourceData.GetRawConfig()
	panic("not implemented")
}

func (p *PluginSdkResourceData) GetFromState(key string) interface{} {
	// p.resourceData.GetRawState()
	panic("not implemented")
}

func (p *PluginSdkResourceData) HasChange(key string) bool {
	return p.resourceData.HasChange(key)
}

func (p *PluginSdkResourceData) HasChanges(keys ...string) bool {
	return p.resourceData.HasChanges(keys...)
}

func (p *PluginSdkResourceData) HasChangesExcept(keys ...string) bool {
	return p.resourceData.HasChangesExcept()
}

func (p *PluginSdkResourceData) Id() string {
	return p.resourceData.Id()
}

func (p *PluginSdkResourceData) Set(key string, value interface{}) error {
	return p.resourceData.Set(key, value)
}

func (p *PluginSdkResourceData) SetConnInfo(input map[string]string) {
	p.resourceData.SetConnInfo(input)
}

func (p *PluginSdkResourceData) SetId(id string) {
	p.resourceData.SetId(id)
}

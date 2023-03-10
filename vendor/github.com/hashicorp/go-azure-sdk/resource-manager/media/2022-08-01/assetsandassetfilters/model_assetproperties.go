package assetsandassetfilters

import (
	"time"

	"github.com/hashicorp/go-azure-helpers/lang/dates"
)

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AssetProperties struct {
	AlternateId             *string                       `json:"alternateId,omitempty"`
	AssetId                 *string                       `json:"assetId,omitempty"`
	Container               *string                       `json:"container,omitempty"`
	Created                 *string                       `json:"created,omitempty"`
	Description             *string                       `json:"description,omitempty"`
	LastModified            *string                       `json:"lastModified,omitempty"`
	StorageAccountName      *string                       `json:"storageAccountName,omitempty"`
	StorageEncryptionFormat *AssetStorageEncryptionFormat `json:"storageEncryptionFormat,omitempty"`
}

func (o *AssetProperties) GetCreatedAsTime() (*time.Time, error) {
	if o.Created == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.Created, "2006-01-02T15:04:05Z07:00")
}

func (o *AssetProperties) SetCreatedAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.Created = &formatted
}

func (o *AssetProperties) GetLastModifiedAsTime() (*time.Time, error) {
	if o.LastModified == nil {
		return nil, nil
	}
	return dates.ParseAsFormat(o.LastModified, "2006-01-02T15:04:05Z07:00")
}

func (o *AssetProperties) SetLastModifiedAsTime(input time.Time) {
	formatted := input.Format("2006-01-02T15:04:05Z07:00")
	o.LastModified = &formatted
}

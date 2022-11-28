package accounts

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.

type AccessControl struct {
	DefaultAction *DefaultAction `json:"defaultAction,omitempty"`
	IPAllowList   *[]string      `json:"ipAllowList,omitempty"`
}

package client

import (
	"github.com/hashicorp/go-azure-sdk/resource-manager/machinelearningservices/2022-05-01/machinelearningcomputes"
	"github.com/hashicorp/go-azure-sdk/resource-manager/machinelearningservices/2022-05-01/workspaces"
	"github.com/hashicorp/terraform-provider-azurerm/internal/common"
)

type Client struct {
	ComputeClient    *machinelearningcomputes.MachineLearningComputesClient
	WorkspacesClient *workspaces.WorkspacesClient
}

func NewClient(o *common.ClientOptions) *Client {
	ComputeClient := machinelearningcomputes.NewMachineLearningComputesClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&ComputeClient.Client, o.ResourceManagerAuthorizer)

	WorkspacesClient := workspaces.NewWorkspacesClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&WorkspacesClient.Client, o.ResourceManagerAuthorizer)

	return &Client{
		ComputeClient:    &ComputeClient,
		WorkspacesClient: &WorkspacesClient,
	}
}

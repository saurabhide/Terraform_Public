package client

import (
	"github.com/Azure/azure-sdk-for-go/services/operationalinsights/mgmt/2020-08-01/operationalinsights"
	"github.com/Azure/azure-sdk-for-go/services/preview/operationsmanagement/mgmt/2015-11-01-preview/operationsmanagement"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2019-09-01/querypacks"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/clusters"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/dataexport"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/datasources"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/linkedservices"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/linkedstorageaccounts"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/savedsearches"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/storageinsights"
	"github.com/hashicorp/go-azure-sdk/resource-manager/operationalinsights/2020-08-01/workspaces"
	"github.com/hashicorp/terraform-provider-azurerm/internal/common"
)

type Client struct {
	ClusterClient              *clusters.ClustersClient
	DataExportClient           *dataexport.DataExportClient
	DataSourcesClient          *datasources.DataSourcesClient
	LinkedServicesClient       *linkedservices.LinkedServicesClient
	LinkedStorageAccountClient *linkedstorageaccounts.LinkedStorageAccountsClient
	QueryPacksClient           *querypacks.QueryPacksClient
	SavedSearchesClient        *savedsearches.SavedSearchesClient
	SharedKeysClient           *operationalinsights.SharedKeysClient
	SolutionsClient            *operationsmanagement.SolutionsClient
	StorageInsightsClient      *storageinsights.StorageInsightsClient
	WorkspacesClient           *workspaces.WorkspacesClient
}

func NewClient(o *common.ClientOptions) *Client {
	ClusterClient := clusters.NewClustersClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&ClusterClient.Client, o.ResourceManagerAuthorizer)

	DataExportClient := dataexport.NewDataExportClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&DataExportClient.Client, o.ResourceManagerAuthorizer)

	DataSourcesClient := datasources.NewDataSourcesClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&DataSourcesClient.Client, o.ResourceManagerAuthorizer)

	WorkspacesClient := workspaces.NewWorkspacesClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&WorkspacesClient.Client, o.ResourceManagerAuthorizer)

	SavedSearchesClient := savedsearches.NewSavedSearchesClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&SavedSearchesClient.Client, o.ResourceManagerAuthorizer)

	SharedKeysClient := operationalinsights.NewSharedKeysClientWithBaseURI(o.ResourceManagerEndpoint, o.SubscriptionId)
	o.ConfigureClient(&SharedKeysClient.Client, o.ResourceManagerAuthorizer)

	SolutionsClient := operationsmanagement.NewSolutionsClientWithBaseURI(o.ResourceManagerEndpoint, o.SubscriptionId, "Microsoft.OperationsManagement", "solutions", "testing")
	o.ConfigureClient(&SolutionsClient.Client, o.ResourceManagerAuthorizer)

	StorageInsightsClient := storageinsights.NewStorageInsightsClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&StorageInsightsClient.Client, o.ResourceManagerAuthorizer)

	LinkedServicesClient := linkedservices.NewLinkedServicesClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&LinkedServicesClient.Client, o.ResourceManagerAuthorizer)

	LinkedStorageAccountClient := linkedstorageaccounts.NewLinkedStorageAccountsClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&LinkedStorageAccountClient.Client, o.ResourceManagerAuthorizer)

	QueryPacksClient := querypacks.NewQueryPacksClientWithBaseURI(o.ResourceManagerEndpoint)
	o.ConfigureClient(&QueryPacksClient.Client, o.ResourceManagerAuthorizer)

	return &Client{
		ClusterClient:              &ClusterClient,
		DataExportClient:           &DataExportClient,
		DataSourcesClient:          &DataSourcesClient,
		LinkedServicesClient:       &LinkedServicesClient,
		LinkedStorageAccountClient: &LinkedStorageAccountClient,
		QueryPacksClient:           &QueryPacksClient,
		SavedSearchesClient:        &SavedSearchesClient,
		SharedKeysClient:           &SharedKeysClient,
		SolutionsClient:            &SolutionsClient,
		StorageInsightsClient:      &StorageInsightsClient,
		WorkspacesClient:           &WorkspacesClient,
	}
}

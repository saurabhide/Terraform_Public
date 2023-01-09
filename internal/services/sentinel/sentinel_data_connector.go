package sentinel

import (
	"fmt"

	securityinsight "github.com/tombuildsstuff/kermit/sdk/securityinsights/2022-10-01-preview/securityinsights"
)

func assertDataConnectorKind(dc securityinsight.BasicDataConnector, expectKind securityinsight.DataConnectorKind) error {
	var kind securityinsight.DataConnectorKind
	switch dc.(type) {
	case securityinsight.AADDataConnector:
		kind = securityinsight.DataConnectorKindAzureActiveDirectory
	case securityinsight.AATPDataConnector:
		kind = securityinsight.DataConnectorKindAzureAdvancedThreatProtection
	case securityinsight.ASCDataConnector:
		kind = securityinsight.DataConnectorKindAzureSecurityCenter
	case securityinsight.MCASDataConnector:
		kind = securityinsight.DataConnectorKindMicrosoftCloudAppSecurity
	case securityinsight.TIDataConnector:
		kind = securityinsight.DataConnectorKindThreatIntelligence
	case securityinsight.MTPDataConnector:
		kind = securityinsight.DataConnectorKindMicrosoftThreatProtection
	case securityinsight.IoTDataConnector:
		kind = securityinsight.DataConnectorKindIOT
	case securityinsight.Dynamics365DataConnector:
		kind = securityinsight.DataConnectorKindDynamics365
	case securityinsight.Office365ProjectDataConnector:
		kind = securityinsight.DataConnectorKindOffice365Project
	case securityinsight.OfficeIRMDataConnector:
		kind = securityinsight.DataConnectorKindOfficeIRM
	case securityinsight.OfficeDataConnector:
		kind = securityinsight.DataConnectorKindOffice365
	case securityinsight.OfficeATPDataConnector:
		kind = securityinsight.DataConnectorKindOfficeATP
	case securityinsight.OfficePowerBIDataConnector:
		kind = securityinsight.DataConnectorKindOfficePowerBI
	case securityinsight.AwsCloudTrailDataConnector:
		kind = securityinsight.DataConnectorKindAmazonWebServicesCloudTrail
	case securityinsight.MDATPDataConnector:
		kind = securityinsight.DataConnectorKindMicrosoftDefenderAdvancedThreatProtection
	case securityinsight.AwsS3DataConnector:
		kind = securityinsight.DataConnectorKindAmazonWebServicesS3
	}
	if expectKind != kind {
		return fmt.Errorf("Sentinel Data Connector has mismatched kind, expected: %q, got %q", expectKind, kind)
	}
	return nil
}

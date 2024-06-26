package cloudproviders

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Khan/genqlient/graphql"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/util"
)

//go:generate go run -mod=mod github.com/Khan/genqlient genqlient.yaml

type CloudProvidersClient struct {
	graphqlClient graphql.Client
}

func NewCloudProvidersClient(url string, httpClient *http.Client) *CloudProvidersClient {
	return &CloudProvidersClient{
		graphqlClient: graphql.NewClient(url, httpClient),
	}
}

func (c *CloudProvidersClient) GetCloudProviderByName(ctx context.Context, name string) (*domain.CloudProvider, error) {
	if name == "" {
		return nil, fmt.Errorf("cloud provider name cannot be empty")
	}
	resp, err := GetCloudProviderByName(ctx, c.graphqlClient, name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Provider with name %s: %w", name, err)
	}
	if resp == nil || resp.GetCloudProviders() == nil || len(resp.GetCloudProviders().Nodes) != 1 {
		return nil, fmt.Errorf("could not find Cloud Provider with name %s", name)
	}

	cp := resp.GetCloudProviders().Nodes[0]

	statusDetails := ""
	if cp.GetStatusDetails() != nil {
		statusDetails = *cp.GetStatusDetails()
	}

	return &domain.CloudProvider{
		ID:             cp.GetId(),
		Name:           cp.GetName(),
		Type:           string(cp.GetType()),
		Status:         string(cp.GetStatus()),
		StatusDetails:  statusDetails,
		KeystoresCount: cp.GetKeystoresCount(),
	}, nil
}

func (c *CloudProvidersClient) GetCloudKeystore(ctx context.Context, cloudKeystoreID *string, cloudKeystoreName *string, cloudProviderName *string) (*domain.CloudKeystore, error) {

	if cloudKeystoreID == nil {
		if cloudKeystoreName == nil || cloudProviderName == nil {
			return nil, fmt.Errorf("following are accepted for provisioning: keystore ID, or both keystore Name and provider Name")
		}
	}

	keystoreIDInput := util.StringPointerToString(cloudKeystoreID)
	keystoreNameInput := util.StringPointerToString(cloudKeystoreName)
	providerNameInput := util.StringPointerToString(cloudProviderName)
	resp, err := GetCloudKeystores(ctx, c.graphqlClient, cloudKeystoreID, cloudKeystoreName, nil, cloudProviderName)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Keystore with KeystoreID: %s, KeystoreName: %s, ProviderName: %s: %w", keystoreIDInput, keystoreNameInput, providerNameInput, err)
	}

	if resp == nil || resp.CloudKeystores == nil {
		return nil, fmt.Errorf("could not find keystore with KeystoreID: %s, KeystoreName: %s, ProviderName: %s", keystoreIDInput, keystoreNameInput, providerNameInput)
	}

	if len(resp.CloudKeystores.Nodes) != 1 {
		return nil, fmt.Errorf("could not find keystore with with KeystoreID: %s, KeystoreName: %s, ProviderName: %s", keystoreIDInput, keystoreNameInput, providerNameInput)
	}

	ck := resp.CloudKeystores.Nodes[0]

	return &domain.CloudKeystore{
		ID:   ck.GetId(),
		Name: ck.GetName(),
		Type: string(ck.GetType()),
	}, nil
}

func (c *CloudProvidersClient) ProvisionCertificate(ctx context.Context, certificateID string, cloudKeystoreID string, wsClientID string, options *CertificateProvisioningOptionsInput) (*domain.ProvisioningResponse, error) {
	if certificateID == "" {
		return nil, fmt.Errorf("certificateID cannot be empty")
	}
	if cloudKeystoreID == "" {
		return nil, fmt.Errorf("cloudKeystoreID cannot be empty")
	}
	if wsClientID == "" {
		return nil, fmt.Errorf("wsClientID cannot be empty")
	}
	resp, err := ProvisionCertificate(ctx, c.graphqlClient, certificateID, cloudKeystoreID, wsClientID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to provision certificate with certificate ID %s, keystore ID %s and websocket ID %s: %w", certificateID, cloudKeystoreID, wsClientID, err)
	}

	if resp == nil || resp.ProvisionToCloudKeystore == nil {
		return nil, fmt.Errorf("failed to provision certificate with certificate ID %s, keystore ID %s and websocket ID %s", certificateID, cloudKeystoreID, wsClientID)
	}

	return &domain.ProvisioningResponse{
		WorkflowId:   resp.GetProvisionToCloudKeystore().GetWorkflowId(),
		WorkflowName: resp.GetProvisionToCloudKeystore().GetWorkflowName(),
	}, nil
}

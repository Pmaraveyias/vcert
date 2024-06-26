package main

import (
	"crypto/x509/pkix"
	"log"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
)

const (
	vcpURL       = "VCP_URL"
	vcpZone      = "VCP_ZONE"
	vcpApiKey    = "CLOUD_APIKEY"
	vcpTokenURL  = "VCP_TOKEN_URL"
	vcpJWT       = "VCP_JWT"
	envVarNotSet = "environment variable not set: %s"

	name = "example-provisioning"
)

func main() {

	// URL can be nil if using production TLSPC
	url := os.Getenv(vcpURL)

	zone, found := os.LookupEnv(vcpZone)
	if !found {
		log.Fatalf(envVarNotSet, vcpZone)
	}

	tokenURL, found := os.LookupEnv(vcpTokenURL)
	if !found {
		log.Fatalf(envVarNotSet, vcpTokenURL)
	}
	jwt, found := os.LookupEnv(vcpJWT)
	if !found {
		log.Fatalf(envVarNotSet, vcpJWT)
	}

	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       url,
		Zone:          zone,
		Credentials: &endpoint.Authentication{
			ExternalJWT: jwt,
			TokenURL:    tokenURL,
		},
	}

	connector, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}

	request := &certificate.Request{
		Subject: pkix.Name{
			CommonName:         "common.name.venafi.example.com",
			Organization:       []string{"Venafi.com"},
			OrganizationalUnit: []string{"Integration Team"},
			Locality:           []string{"Salt Lake"},
			Province:           []string{"Salt Lake"},
			Country:            []string{"US"},
		},
		DNSNames:  []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
		CsrOrigin: certificate.ServiceGeneratedCSR,
		KeyType:   certificate.KeyTypeRSA,
		KeyLength: certificate.DefaultRSAlength,
	}

	err = connector.GenerateRequest(nil, request)
	if err != nil {
		log.Fatalf("could not generate certificate request: %s", err)
	}

	requestID, err := connector.RequestCertificate(request)
	if err != nil {
		log.Fatalf("could not submit certificate request: %s", err)
	}
	log.Printf("Successfully submitted certificate request. Will pickup certificate by ID %s", requestID)

	keystoreName := "<insert Keystore Name here>"
	providerName := "<insert Provider Name here>"
	certName := "<insert cert name>" // e.g. test2-venafi-com

	// The ID is the Certificate name for Google, hence we send it as name
	optionsGcp := &cloud.CloudProvisioningGCPOptions{
		ID: &certName,
	}

	// Example for Azure Options
	// optionsAzure := &cloud.CloudProvisioningAzureOptions{
	//   Name: &certName,
	// }
	//
	// optionsInput := endpoint.ProvisioningOptions(optionsAzure)

	optionsInput := endpoint.ProvisioningOptions(optionsGcp)

	req := &endpoint.ProvisioningRequest{
		KeystoreName: &keystoreName,
		ProviderName: &providerName,
		PickupID:     &requestID,
	}

	certMetaData, err := connector.ProvisionCertificate(req, &optionsInput)
	if err != nil {
		log.Fatalf("error provisioning: %s", err.Error())
	}

	// Example to get values from other keystores machine identities metadata
	//log.Printf("Certificate AWS Metadata ARN:\n%v", certMetaData.GetAWSCertificateMetadata().GetARN())
	//log.Printf("Certificate Azure Metadata ID:\n%v", certMetaData.GetAzureCertificateMetadata().GetID())
	//log.Printf("Certificate Azure Metadata Name:\n%v", certMetaData.GetAzureCertificateMetadata().GetName())
	//log.Printf("Certificate Azure Metadata Version:\n%v", certMetaData.GetAzureCertificateMetadata().GetVersion())
	log.Printf("Certificate GCP Metadata ID:\n%v", certMetaData.GetGCPCertificateMetadata().GetID())
	log.Printf("Certificate GCP Metadata Name:\n%v", certMetaData.GetGCPCertificateMetadata().GetName())
}

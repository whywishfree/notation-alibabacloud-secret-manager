// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"

	"github.com/AliyunContainerService/ack-ram-tool/pkg/ctl/common"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/crypto"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/log"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/sm"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/version"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/types"
)

const (
	PluginName    = "notation"
	CaCerts       = "ca_certs"
	CertOutputDir = "output_cert_dir"
	KeyVersionId  = "key_version_id"
	suffix        = "cryptoservice.kms.aliyuncs.com"
)

type AlibabaCloudSecretManagerPlugin struct {
	clientProvider types.ClientProvider
}

func NewAlibabaCloudSecretManagerPlugin() (*AlibabaCloudSecretManagerPlugin, error) {
	var clientProvider types.ClientProvider
	var err error
	client := common.GetClientOrDie()
	config := openapi.Config{
		RegionId:   tea.String(sm.GetKMSRegionId()),
		Credential: client.Credential(),
	}
	instanceEndpoint := sm.GetInstanceEndpoint()
	if instanceEndpoint == "" {
		return nil, errors.New("env ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT MUST be set for kms instance endpoint")
	}
	clientKey := sm.GetClientKey()
	kmsPassword := sm.GetKMSPassword()
	if clientKey != "" && kmsPassword != "" {
		clientProvider, err = NewDKMSClientImpl(clientKey, kmsPassword, instanceEndpoint, config)
		if err != nil {
			return nil, fmt.Errorf("new dkms client failed: %v", err)
		}
	} else {
		if strings.Contains(instanceEndpoint, suffix) {
			config.Ca = tea.String(sm.GetKMSCAFile())
		}
		config.Endpoint = tea.String(instanceEndpoint)
		clientProvider, err = NewKMSClientImpl(config)
		if err != nil {
			return nil, fmt.Errorf("new kms client failed: %v", err)
		}
	}

	return &AlibabaCloudSecretManagerPlugin{
		clientProvider: clientProvider,
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) DescribeKey(_ context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	request := &kms.DescribeKeyRequest{
		KeyId: tea.String(req.KeyID),
	}
	keyResult := &kms.DescribeKeyResponse{}
	response, err := p.clientProvider.GetKMSClient().DescribeKey(request)
	if err != nil {
		return nil, err
	}
	keyResult = response
	smKeySpec := keyResult.Body.KeyMetadata.KeySpec
	if keyResult.Body == nil || keyResult.Body.KeyMetadata == nil || keyResult.Body.KeyMetadata.KeySpec == nil {
		return nil, errors.New("failed to describe key")
	}
	keySpec, err := sm.SwitchKeySpec(tea.StringValue(smKeySpec))
	if err != nil {
		return nil, err
	}
	return &plugin.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: keySpec,
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GenerateSignature(ctx context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {
	rawCertChain := make([][]byte, 0)
	signature, err := p.clientProvider.GenerateSignature(&types.SignRequest{
		KeyId:        req.KeyID,
		KeyVersionId: req.PluginConfig[KeyVersionId],
		MessageType:  "RAW",
		Payload:      req.Payload,
		Algorithm:    "RSA_PSS_SHA_256",
	})
	if err != nil {
		log.Logger.Errorf("Failed to sign with key %s, err %v", req.KeyID, err)
		return nil, err
	}
	var certChain []*x509.Certificate
	if caCertsPath, ok := req.PluginConfig[CaCerts]; ok {
		//for imported key
		caCertPEMBlock, err := os.ReadFile(caCertsPath)
		if err != nil {
			log.Logger.Errorf("Failed to read ca_certs from %s, err %v", caCertsPath, err)
			return nil, err
		}
		certChain, err = crypto.ParseCertificates(caCertPEMBlock)
		if err != nil {
			log.Logger.Errorf("Failed to parse ca_certs from %s, err %v", caCertsPath, err)
			return nil, err
		}
		// build raw cert chain
		for _, cert := range certChain {
			rawCertChain = append(rawCertChain, cert.Raw)
		}
	} else {
		//for kms self generated key
		pub, err := p.clientProvider.GetPublicKey(req.KeyID, req.PluginConfig[KeyVersionId])
		if err != nil {
			log.Logger.Errorf("Failed to get the public key from the given kms key %s, err %v", req.KeyID, err)
			return nil, err
		}
		//get cert data based on the given key id
		certData, err := sm.GetCertDataFromKey(p.clientProvider, pub, req.KeyID, req.PluginConfig[KeyVersionId])
		if err != nil {
			log.Logger.Errorf("Failed to parse ca_certs from %s, err %v", caCertsPath, err)
			return nil, err
		}
		err = sm.CertDataOutput(certData, req.PluginConfig[CertOutputDir])
		if err != nil {
			log.Logger.Errorf("Failed to parse ca_certs from %s, err %v", caCertsPath, err)
			return nil, err
		}

		rawCertChain = append(rawCertChain, certData)
	}
	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        signature,
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA256,
		CertificateChain: rawCertChain,
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GenerateEnvelope(_ context.Context, _ *plugin.GenerateEnvelopeRequest) (*plugin.GenerateEnvelopeResponse, error) {

	return nil, plugin.NewUnsupportedError("GenerateSignature operation is not implemented by this plugin")
}

func (p *AlibabaCloudSecretManagerPlugin) VerifySignature(_ context.Context, req *plugin.VerifySignatureRequest) (*plugin.VerifySignatureResponse, error) {
	upAttrs := req.Signature.UnprocessedAttributes
	pAttrs := make([]interface{}, len(upAttrs))
	for i := range upAttrs {
		pAttrs[i] = upAttrs[i]
	}

	return &plugin.VerifySignatureResponse{
		ProcessedAttributes: pAttrs,
		VerificationResults: map[plugin.Capability]*plugin.VerificationResult{
			plugin.CapabilityTrustedIdentityVerifier: {
				Success: true,
				Reason:  "Valid trusted Identity",
			},
			plugin.CapabilityRevocationCheckVerifier: {
				Success: true,
				Reason:  "Not revoked",
			},
		},
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GetMetadata(_ context.Context, _ *plugin.GetMetadataRequest) (*plugin.GetMetadataResponse, error) {
	return &plugin.GetMetadataResponse{
		SupportedContractVersions: []string{plugin.ContractVersion},
		Name:                      "alibabacloud.secretmanager.plugin",
		Description:               "Alibaba Cloud Secret Manager signer plugin for Notation",
		URL:                       "https://example.com/notation/plugin",
		Version:                   version.Version,
		Capabilities: []plugin.Capability{
			plugin.CapabilitySignatureGenerator,
			plugin.CapabilityTrustedIdentityVerifier},
	}, nil
}

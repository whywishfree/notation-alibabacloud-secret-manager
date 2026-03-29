package plugin

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/sm"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/types"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapiutil "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi-util"
	dkms "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"os"
)

type DKMSClientImpl struct {
	client    *dkms.Client
	kmsClient *kms.Client
}

func NewDKMSClientImpl(clientKey, kmsPassword, instanceEndpoint string, config openapi.Config) (*DKMSClientImpl, error) {
	dkmsClient, err := sm.GetDkmsClientByClientKeyFile(clientKey, kmsPassword, instanceEndpoint)
	if err != nil {
		return nil, err
	}
	kmsClient, err := kms.NewClient(&config)
	if err != nil {
		return nil, err
	}
	return &DKMSClientImpl{
		client:    dkmsClient,
		kmsClient: kmsClient,
	}, nil
}

func (d *DKMSClientImpl) GenerateSignature(req *types.SignRequest) ([]byte, error) {
	signRequest := &dkms.SignRequest{
		KeyId:       tea.String(req.KeyId),
		Message:     req.Payload,
		MessageType: tea.String(req.MessageType),
		Algorithm:   tea.String(req.Algorithm),
	}
	runtimeOptions := &dedicatedkmsopenapiutil.RuntimeOptions{
		IgnoreSSL: tea.Bool(true),
	}

	//set instance ca from file
	caFilePath := sm.GetKMSCAFile()
	if caFilePath != "" {
		certPEMBlock, err := os.ReadFile(caFilePath)
		if err != nil {
			return nil, err
		}
		certDERBlock, _ := pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			return nil, fmt.Errorf("cert is nil")
		}
		cert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %s, err: %v", caFilePath, err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("the provided certificate is not a CA certificate")
		}
		runtimeOptions = &dedicatedkmsopenapiutil.RuntimeOptions{
			Verify: tea.String(string(certPEMBlock)),
		}
	}
	sigResp, err := d.client.SignWithOptions(signRequest, runtimeOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload %v", err)
	}
	return sigResp.Signature, nil
}

func (d *DKMSClientImpl) GetPublicKey(keyId, keyVersionId string) (*rsa.PublicKey, error) {
	request := &dkms.GetPublicKeyRequest{
		KeyId: tea.String(keyId),
	}
	response, err := d.client.GetPublicKey(request)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(*response.PublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	//return rsa public key
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New(fmt.Sprintf("unsupport public key type %T", pub))
	}

	return rsaPub, nil
}

func (d *DKMSClientImpl) GetKMSClient() *kms.Client {
	return d.kmsClient
}

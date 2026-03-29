package plugin

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/log"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/types"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
)

type KMSClientImpl struct {
	client *kms.Client
}

func NewKMSClientImpl(config openapi.Config) (*KMSClientImpl, error) {
	kmsClient, err := kms.NewClient(&config)
	if err != nil {
		return nil, err
	}
	return &KMSClientImpl{
		client: kmsClient,
	}, nil
}

func (k *KMSClientImpl) GenerateSignature(req *types.SignRequest) ([]byte, error) {
	var hashContent = req.Payload
	if req.MessageType != "DIGEST" {
		hash := sha256.New()
		hash.Write(req.Payload)
		hashContent = hash.Sum(nil)
	}
	base64EncodeHash := base64.StdEncoding.EncodeToString(hashContent)
	resp, err := k.client.AsymmetricSign(&kms.AsymmetricSignRequest{
		Algorithm:    tea.String(req.Algorithm),
		Digest:       tea.String(base64EncodeHash),
		KeyId:        tea.String(req.KeyId),
		KeyVersionId: tea.String(req.KeyVersionId),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload %v", err)
	}
	if resp.Body == nil || resp.Body.Value == nil {
		return nil, fmt.Errorf("failed to sign with key %s, resp body is nil", req.KeyId)
	}
	decodeSig, err := base64.StdEncoding.DecodeString(tea.StringValue(resp.Body.Value))
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature %v", err)
	}
	return decodeSig, nil
}

func (k *KMSClientImpl) GetPublicKey(keyId, keyVersionId string) (*rsa.PublicKey, error) {
	resp, err := k.client.GetPublicKey(&kms.GetPublicKeyRequest{
		KeyId:        tea.String(keyId),
		KeyVersionId: tea.String(keyVersionId),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key %v", err)
	}
	if resp == nil || resp.Body == nil || resp.Body.PublicKey == nil {
		return nil, fmt.Errorf("failed to get public key")
	}
	block, _ := pem.Decode([]byte(*resp.Body.PublicKey))
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
	log.Logger.Infof("rsapub is %v", rsaPub.Size())
	return rsaPub, nil
}

func (k *KMSClientImpl) GetKMSClient() *kms.Client {
	return k.client
}

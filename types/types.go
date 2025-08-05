package types

import (
	"crypto/rsa"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
)

type ClientProvider interface {
	GenerateSignature(req *SignRequest) (string, error)
	GetPublicKey(keyId, keyVersionId string) (*rsa.PublicKey, error)
	GetKMSClient() *kms.Client
}

type SignRequest struct {
	KeyId        string
	KeyVersionId string
	MessageType  string
	Payload      []byte
	Algorithm    string
}

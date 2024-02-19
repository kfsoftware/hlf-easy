package utils

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"hlf-easy/config"
	"os"
	"path/filepath"
)

type CAConfig struct {
	CACert *x509.Certificate
	CAKey  *ecdsa.PrivateKey

	TLSCACert *x509.Certificate
	TLSCAKey  *ecdsa.PrivateKey
}

func GetCAConfig(name string) (*CAConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	caConfigFilePath := filepath.Join(
		home,
		fmt.Sprintf("hlf-easy/cas/%s/config.json", name),
	)
	// check if file exists
	if _, err := os.Stat(caConfigFilePath); os.IsNotExist(err) {
		return nil, errors.Errorf("ca config file does not exist: %v", caConfigFilePath)
	}
	// read config ca file
	caConfigBytes, err := os.ReadFile(caConfigFilePath)
	if err != nil {
		return nil, err
	}
	caConfig := config.CAConfig{}
	err = json.Unmarshal(caConfigBytes, &caConfig)
	if err != nil {
		return nil, err
	}
	// parse CA Cert and Key
	caCert, err := ParseX509Certificate(caConfig.CaCert)
	if err != nil {
		return nil, err
	}
	caKey, err := ParseECDSAPrivateKey(caConfig.CaKey)
	if err != nil {
		return nil, err
	}
	// parse TLS CA Cert and Key
	tlsCACert, err := ParseX509Certificate(caConfig.TlsCACert)
	if err != nil {
		return nil, err
	}
	tlsCAKey, err := ParseECDSAPrivateKey(caConfig.TlsCAKey)
	if err != nil {
		return nil, err
	}
	return &CAConfig{
		CACert:    caCert,
		CAKey:     caKey,
		TLSCACert: tlsCACert,
		TLSCAKey:  tlsCAKey,
	}, nil
}

type PeerConfig struct {
	TLSKey   *ecdsa.PrivateKey
	TLSCert  *x509.Certificate
	SignKey  *ecdsa.PrivateKey
	SignCert *x509.Certificate

	TLSCACert *x509.Certificate
	CaCert    *x509.Certificate
}

func GetPeerConfig(name string) (*PeerConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	caConfigFilePath := filepath.Join(
		home,
		fmt.Sprintf("hlf-easy/peers/%s/config.json", name),
	)
	// check if file exists
	if _, err := os.Stat(caConfigFilePath); os.IsNotExist(err) {
		return nil, errors.Errorf("peer config file does not exist: %v", caConfigFilePath)
	}
	// read config ca file
	caConfigBytes, err := os.ReadFile(caConfigFilePath)
	if err != nil {
		return nil, err
	}
	caConfig := config.PeerConfig{}
	err = json.Unmarshal(caConfigBytes, &caConfig)
	if err != nil {
		return nil, err
	}
	// parse CA Cert and Key
	signCert, err := ParseX509Certificate(caConfig.SignCert)
	if err != nil {
		return nil, err
	}
	signKey, err := ParseECDSAPrivateKey(caConfig.SignKey)
	if err != nil {
		return nil, err
	}
	// parse TLS CA Cert and Key
	tlsCert, err := ParseX509Certificate(caConfig.TLSCert)
	if err != nil {
		return nil, err
	}
	tlsKey, err := ParseECDSAPrivateKey(caConfig.TLSKey)
	if err != nil {
		return nil, err
	}
	tlsCACert, err := ParseX509Certificate(caConfig.TlsCACert)
	if err != nil {
		return nil, err
	}
	caCert, err := ParseX509Certificate(caConfig.CaCert)
	if err != nil {
		return nil, err
	}
	return &PeerConfig{
		TLSKey:    tlsKey,
		TLSCert:   tlsCert,
		SignKey:   signKey,
		SignCert:  signCert,
		TLSCACert: tlsCACert,
		CaCert:    caCert,
	}, nil
}

func GetPeerRunConfig(name string) (*config.PeerRunConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	caConfigFilePath := filepath.Join(
		home,
		fmt.Sprintf("hlf-easy/peers/%s/run.json", name),
	)
	// check if file exists
	if _, err := os.Stat(caConfigFilePath); os.IsNotExist(err) {
		return nil, errors.Errorf("peer run config file does not exist: %v", caConfigFilePath)
	}
	// read config ca file
	caConfigBytes, err := os.ReadFile(caConfigFilePath)
	if err != nil {
		return nil, err
	}
	peerStartOptions := config.PeerRunConfig{}
	err = json.Unmarshal(caConfigBytes, &peerStartOptions)
	if err != nil {
		return nil, err
	}
	return &peerStartOptions, nil
}

type OrdererConfig struct {
	TLSKey   *ecdsa.PrivateKey
	TLSCert  *x509.Certificate
	SignKey  *ecdsa.PrivateKey
	SignCert *x509.Certificate

	TLSCACert *x509.Certificate
	CaCert    *x509.Certificate
}

func GetOrdererConfig(ordererConfigFilePath string) (*OrdererConfig, error) {

	// check if file exists
	if _, err := os.Stat(ordererConfigFilePath); os.IsNotExist(err) {
		return nil, errors.Errorf("peer config file does not exist: %v", ordererConfigFilePath)
	}
	// read config ca file
	caConfigBytes, err := os.ReadFile(ordererConfigFilePath)
	if err != nil {
		return nil, err
	}
	caConfig := config.PeerConfig{}
	err = json.Unmarshal(caConfigBytes, &caConfig)
	if err != nil {
		return nil, err
	}
	// parse CA Cert and Key
	signCert, err := ParseX509Certificate(caConfig.SignCert)
	if err != nil {
		return nil, err
	}
	signKey, err := ParseECDSAPrivateKey(caConfig.SignKey)
	if err != nil {
		return nil, err
	}
	// parse TLS CA Cert and Key
	tlsCert, err := ParseX509Certificate(caConfig.TLSCert)
	if err != nil {
		return nil, err
	}
	tlsKey, err := ParseECDSAPrivateKey(caConfig.TLSKey)
	if err != nil {
		return nil, err
	}
	tlsCACert, err := ParseX509Certificate(caConfig.TlsCACert)
	if err != nil {
		return nil, err
	}
	caCert, err := ParseX509Certificate(caConfig.CaCert)
	if err != nil {
		return nil, err
	}
	return &OrdererConfig{
		TLSKey:    tlsKey,
		TLSCert:   tlsCert,
		SignKey:   signKey,
		SignCert:  signCert,
		TLSCACert: tlsCACert,
		CaCert:    caCert,
	}, nil
}

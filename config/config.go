package config

type CAConfig struct {
	CaCert    []byte `json:"caCert"`
	CaKey     []byte `json:"caKey"`
	CaName    string `json:"caName"`
	TlsCACert []byte `json:"tlsCACert"`
	TlsCAKey  []byte `json:"tlsCAKey"`
	TlsCert   []byte `json:"tlsCert"`
	TlsKey    []byte `json:"tlsKey"`
}
type PeerRunConfig struct {
	PeerID  string           `json:"peerID"`
	Options PeerStartOptions `json:"options"`
}
type PeerConfig struct {
	TlsCACert []byte `json:"tlsCACert"`
	CaCert    []byte `json:"caCert"`

	TLSKey   []byte `json:"tlsKey"`
	TLSCert  []byte `json:"tlsCert"`
	SignKey  []byte `json:"signKey"`
	SignCert []byte `json:"signCert"`
	PeerID   string `json:"peerID"`
}
type OrdererConfig struct {
	TlsCACert []byte `json:"tlsCACert"`
	CaCert    []byte `json:"caCert"`

	TLSKey   []byte `json:"tlsKey"`
	TLSCert  []byte `json:"tlsCert"`
	SignKey  []byte `json:"signKey"`
	SignCert []byte `json:"signCert"`
	PeerID   string `json:"peerID"`
}

type OrdererRunConfig struct {
	OrdererID string              `json:"ordererID"`
	Options   OrdererStartOptions `json:"options"`
}
type OrdererInitOptions struct {
	CAUrl        string `json:"caUrl"`
	CAInsecure   bool   `json:"caInsecure"`
	CACert       string `json:"caCert"`
	EnrollID     string `json:"enrollID"`
	EnrollSecret string `json:"enrollSecret"`
	ID           string `json:"id"`

	Local  bool   `json:"local"`
	CAName string `json:"caName"`

	Hosts []string `json:"hosts"`
}
type PeerInitOptions struct {
	CAUrl        string `json:"caUrl"`
	CAInsecure   bool   `json:"caInsecure"`
	CACert       string `json:"caCert"`
	EnrollID     string `json:"enrollID"`
	EnrollSecret string `json:"enrollSecret"`
	ID           string `json:"id"`

	Local  bool   `json:"local"`
	CAName string `json:"caName"`

	Hosts []string `json:"hosts"`
}
type StartPeerOpts struct {
	ID string

	ListenAddress           string
	ChaincodeAddress        string
	EventsAddress           string
	OperationsListenAddress string

	ExternalEndpoint string
	MSPID            string

	MSPConfigPath string

	ConfigPeerPath string
}

type StartOrdererOpts struct {
	ID string

	ListenAddress           string
	OperationsListenAddress string
	AdminListenAddress      string

	ExternalEndpoint string
	MSPID            string

	MSPConfigPath string

	ConfigOrdererPath string
}
type PeerStartOptions struct {
	ID                      string `json:"id"`
	ListenAddress           string `json:"listenAddress"`
	ChaincodeAddress        string `json:"chaincodeAddress"`
	EventsAddress           string `json:"eventsAddress"`
	OperationsListenAddress string `json:"operationsListenAddress"`
	ExternalEndpoint        string `json:"externalEndpoint"`
	MSPID                   string `json:"mspID"`
	ManagementAddress       string `json:"managementAddress"`
}

type OrdererStartOptions struct {
	ID                      string `json:"id"`
	ListenAddress           string `json:"listenAddress"`
	AdminListenAddress      string `json:"adminListenAddress"`
	OperationsListenAddress string `json:"operationsListenAddress"`
	ExternalEndpoint        string `json:"externalEndpoint"`
	MSPID                   string `json:"mspID"`
	ManagementAddress       string `json:"managementAddress"`
}

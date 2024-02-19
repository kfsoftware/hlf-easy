package node

import (
	"encoding/json"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"
	"hlf-easy/certs"
	"hlf-easy/config"
	"hlf-easy/utils"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

type OrdererNode struct {
	id        string
	cmdGetter func() (*exec.Cmd, error)
	cmd       *exec.Cmd
	p         *process.Process
	mspID     string
}

type OrdererConfig struct {
	TLSCert  string `json:"tlsCert"`
	SignCert string `json:"signCert"`

	TLSCACert  string `json:"tlsCACert"`
	SignCACert string `json:"signCACert"`
}

func (n *OrdererNode) GetConfig() (*OrdererConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	ordererDir := filepath.Join(home, fmt.Sprintf("hlf-easy/orderers/%s", n.id))
	tlsCertBytes, err := os.ReadFile(filepath.Join(ordererDir, "tls.crt"))
	if err != nil {
		return nil, err
	}
	signCertBytes, err := os.ReadFile(filepath.Join(ordererDir, "signcerts/cert.pem"))
	if err != nil {
		return nil, err
	}
	signCACertBytes, err := os.ReadFile(filepath.Join(ordererDir, "cacerts/cacert.pem"))
	if err != nil {
		return nil, err
	}
	tlsCACertBytes, err := os.ReadFile(filepath.Join(ordererDir, "tlscacerts/cacert.pem"))
	if err != nil {
		return nil, err
	}
	return &OrdererConfig{
		TLSCert:  string(tlsCertBytes),
		SignCert: string(signCertBytes),

		TLSCACert:  string(tlsCACertBytes),
		SignCACert: string(signCACertBytes),
	}, nil
}

func (n *OrdererNode) GetID() string {
	return n.id
}

func (n *OrdererNode) GetMSPID() string {
	return n.mspID
}

func (n *OrdererNode) Start() error {
	if n.cmd != nil {
		log.Info("Orderer node is already started")
		return errors.New("orderer node is already started")
	}
	cmd, err := n.cmdGetter()
	if err != nil {
		log.Warnf("Failed to get orderer node command: %v", err)
		return err
	}
	n.cmd = cmd
	if err := n.cmd.Start(); err != nil {
		log.Warnf("Failed to start orderer node: %v", err)
		return err
	}

	p, err := process.NewProcess(int32(n.cmd.Process.Pid))
	if err != nil {
		log.Warnf("Failed to get orderer node process: %v", err)
		return err
	}
	n.p = p
	return nil
}

func (n *OrdererNode) Stop() error {
	if n.cmd == nil || n.cmd.Process == nil {
		log.Info("Orderer node is already stopped")
		return errors.New("orderer node is already stopped")
	}
	err := n.cmd.Process.Signal(os.Interrupt)
	if err != nil {
		log.Warnf("Failed to stop orderer node: %v", err)
		return err
	}
	state, err := n.cmd.Process.Wait()
	if err != nil {
		log.Warnf("Failed to stop orderer node: %v", err)
		return err
	}
	_ = state
	n.cmd = nil
	return nil
}

func (n *OrdererNode) Status() (*ProcessState, error) {
	if n.cmd == nil || n.cmd.Process == nil {
		return &ProcessState{
			PID:    0,
			Status: "Stop",
			MemoryInfo: &process.MemoryInfoStat{
				RSS:    0,
				VMS:    0,
				HWM:    0,
				Data:   0,
				Stack:  0,
				Locked: 0,
				Swap:   0,
			},
			CPUInfo: CPUInfo{
				CPUPercent: 0,
			},
		}, nil
	}

	status, err := n.p.Status()
	if err != nil {
		log.Warnf("Failed to get orderer node status: %v", err)
		return nil, err
	}
	statusStr, ok := StatusMap[status]
	if !ok {
		statusStr = "Unknown"
	}
	memoryInfo, err := n.p.MemoryInfo()
	if err != nil {
		log.Warnf("Failed to get orderer node memory info: %v", err)
		return nil, err
	}
	cpuPercent, err := n.p.CPUPercent()
	if err != nil {
		log.Warnf("Failed to get orderer node cpu percent: %v", err)
		return nil, err
	}
	ps := &ProcessState{
		PID:        int(n.p.Pid),
		Status:     statusStr,
		MemoryInfo: memoryInfo,
		CPUInfo: CPUInfo{
			CPUPercent: cpuPercent,
		},
	}
	return ps, nil
}

func NewOrdererNode(
	id string,
	mspID string,
	cmdGetter func() (*exec.Cmd, error),
) *OrdererNode {
	return &OrdererNode{
		id:        id,
		mspID:     mspID,
		cmdGetter: cmdGetter,
	}
}

const (
	ordererYamlTemplate = `
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

---
################################################################################
#
#   Orderer Configuration
#
#   - This controls the type and configuration of the orderer.
#
################################################################################
General:
    # Listen address: The IP on which to bind to listen.
    ListenAddress: 127.0.0.1

    # Listen port: The port on which to bind to listen.
    ListenPort: 7050

    # TLS: TLS settings for the GRPC server.
    TLS:
        # Require server-side TLS
        Enabled: false
        # PrivateKey governs the file location of the private key of the TLS certificate.
        PrivateKey: tls/server.key
        # Certificate governs the file location of the server TLS certificate.
        Certificate: tls/server.crt
        # RootCAs contains a list of additional root certificates used for verifying certificates
        # of other orderer nodes during outbound connections.
        # It is not required to be set, but can be used to augment the set of TLS CA certificates
        # available from the MSPs of each channel’s configuration.
        RootCAs:
          - tls/ca.crt
        # Require client certificates / mutual TLS for inbound connections.
        ClientAuthRequired: false
        # If mutual TLS is enabled, ClientRootCAs contains a list of additional root certificates
        # used for verifying certificates of client connections.
        # It is not required to be set, but can be used to augment the set of TLS CA certificates
        # available from the MSPs of each channel’s configuration.
        ClientRootCAs:
    # Keepalive settings for the GRPC server.
    Keepalive:
        # ServerMinInterval is the minimum permitted time between client pings.
        # If clients send pings more frequently, the server will
        # disconnect them.
        ServerMinInterval: 60s
        # ServerInterval is the time between pings to clients.
        ServerInterval: 7200s
        # ServerTimeout is the duration the server waits for a response from
        # a client before closing the connection.
        ServerTimeout: 20s

    # Since all nodes should be consistent it is recommended to keep
    # the default value of 100MB for MaxRecvMsgSize & MaxSendMsgSize
    # Max message size in bytes the GRPC server and client can receive
    MaxRecvMsgSize: 104857600
    # Max message size in bytes the GRPC server and client can send
    MaxSendMsgSize: 104857600

    # Cluster settings for ordering service nodes that communicate with other ordering service nodes
    # such as Raft based ordering service.
    Cluster:
        # SendBufferSize is the maximum number of messages in the egress buffer.
        # Consensus messages are dropped if the buffer is full, and transaction
        # messages are waiting for space to be freed.
        SendBufferSize: 100

        # ClientCertificate governs the file location of the client TLS certificate
        # used to establish mutual TLS connections with other ordering service nodes.
        # If not set, the server General.TLS.Certificate is re-used.
        ClientCertificate:
        # ClientPrivateKey governs the file location of the private key of the client TLS certificate.
        # If not set, the server General.TLS.PrivateKey is re-used.
        ClientPrivateKey:

        # The below 4 properties should be either set together, or be unset together.
        # If they are set, then the orderer node uses a separate listener for intra-cluster
        # communication. If they are unset, then the general orderer listener is used.
        # This is useful if you want to use a different TLS server certificates on the
        # client-facing and the intra-cluster listeners.

        # ListenPort defines the port on which the cluster listens to connections.
        ListenPort:
        # ListenAddress defines the IP on which to listen to intra-cluster communication.
        ListenAddress:
        # ServerCertificate defines the file location of the server TLS certificate used for intra-cluster
        # communication.
        ServerCertificate:
        # ServerPrivateKey defines the file location of the private key of the TLS certificate.
        ServerPrivateKey:

    # Bootstrap method: The method by which to obtain the bootstrap block
    # system channel is specified. The option can be one of:
    #   "file" - path to a file containing the genesis block or config block of system channel
    #   "none" - allows an orderer to start without a system channel configuration
    BootstrapMethod: file

    # Bootstrap file: The file containing the bootstrap block to use when
    # initializing the orderer system channel and BootstrapMethod is set to
    # "file".  The bootstrap file can be the genesis block, and it can also be
    # a config block for late bootstrap of some consensus methods like Raft.
    # Generate a genesis block by updating $FABRIC_CFG_PATH/configtx.yaml and
    # using configtxgen command with "-outputBlock" option.
    # Defaults to file "genesisblock" (in $FABRIC_CFG_PATH directory) if not specified.
    BootstrapFile:

    # LocalMSPDir is where to find the private crypto material needed by the
    # orderer. It is set relative here as a default for dev environments but
    # should be changed to the real location in production.
    LocalMSPDir: msp

    # LocalMSPID is the identity to register the local MSP material with the MSP
    # manager. IMPORTANT: The local MSP ID of an orderer needs to match the MSP
    # ID of one of the organizations defined in the orderer system channel's
    # /Channel/Orderer configuration. The sample organization defined in the
    # sample configuration provided has an MSP ID of "SampleOrg".
    LocalMSPID: SampleOrg

    # Enable an HTTP service for Go "pprof" profiling as documented at:
    # https://golang.org/pkg/net/http/pprof
    Profile:
        Enabled: false
        Address: 0.0.0.0:6060

    # BCCSP configures the blockchain crypto service providers.
    BCCSP:
        # Default specifies the preferred blockchain crypto service provider
        # to use. If the preferred provider is not available, the software
        # based provider ("SW") will be used.
        # Valid providers are:
        #  - SW: a software based crypto provider
        #  - PKCS11: a CA hardware security module crypto provider.
        Default: SW

        # SW configures the software based blockchain crypto provider.
        SW:
            # TODO: The default Hash and Security level needs refactoring to be
            # fully configurable. Changing these defaults requires coordination
            # SHA2 is hardcoded in several places, not only BCCSP
            Hash: SHA2
            Security: 256
            # Location of key store. If this is unset, a location will be
            # chosen using: 'LocalMSPDir'/keystore
            FileKeyStore:
                KeyStore:

        # Settings for the PKCS#11 crypto provider (i.e. when DEFAULT: PKCS11)
        PKCS11:
            # Location of the PKCS11 module library
            Library:
            # Token Label
            Label:
            # User PIN
            Pin:
            Hash:
            Security:
            FileKeyStore:
                KeyStore:

    # Authentication contains configuration parameters related to authenticating
    # client messages
    Authentication:
        # the acceptable difference between the current server time and the
        # client's time as specified in a client request message
        TimeWindow: 15m


################################################################################
#
#   SECTION: File Ledger
#
#   - This section applies to the configuration of the file ledger.
#
################################################################################
FileLedger:

    # Location: The directory to store the blocks in.
    Location: {{ .FileSystemPath }}

################################################################################
#
#   SECTION: Kafka
#
#   - This section applies to the configuration of the Kafka-based orderer, and
#     its interaction with the Kafka cluster.
#
################################################################################
Kafka:

    # Retry: What do if a connection to the Kafka cluster cannot be established,
    # or if a metadata request to the Kafka cluster needs to be repeated.
    Retry:
        # When a new channel is created, or when an existing channel is reloaded
        # (in case of a just-restarted orderer), the orderer interacts with the
        # Kafka cluster in the following ways:
        # 1. It creates a Kafka producer (writer) for the Kafka partition that
        # corresponds to the channel.
        # 2. It uses that producer to post a no-op CONNECT message to that
        # partition
        # 3. It creates a Kafka consumer (reader) for that partition.
        # If any of these steps fail, they will be re-attempted every
        # <ShortInterval> for a total of <ShortTotal>, and then every
        # <LongInterval> for a total of <LongTotal> until they succeed.
        # Note that the orderer will be unable to write to or read from a
        # channel until all of the steps above have been completed successfully.
        ShortInterval: 5s
        ShortTotal: 10m
        LongInterval: 5m
        LongTotal: 12h
        # Affects the socket timeouts when waiting for an initial connection, a
        # response, or a transmission. See Config.Net for more info:
        # https://godoc.org/github.com/Shopify/sarama#Config
        NetworkTimeouts:
            DialTimeout: 10s
            ReadTimeout: 10s
            WriteTimeout: 10s
        # Affects the metadata requests when the Kafka cluster is in the middle
        # of a leader election.See Config.Metadata for more info:
        # https://godoc.org/github.com/Shopify/sarama#Config
        Metadata:
            RetryBackoff: 250ms
            RetryMax: 3
        # What to do if posting a message to the Kafka cluster fails. See
        # Config.Producer for more info:
        # https://godoc.org/github.com/Shopify/sarama#Config
        Producer:
            RetryBackoff: 100ms
            RetryMax: 3
        # What to do if reading from the Kafka cluster fails. See
        # Config.Consumer for more info:
        # https://godoc.org/github.com/Shopify/sarama#Config
        Consumer:
            RetryBackoff: 2s
    # Settings to use when creating Kafka topics.  Only applies when
    # Kafka.Version is v0.10.1.0 or higher
    Topic:
        # The number of Kafka brokers across which to replicate the topic
        ReplicationFactor: 3
    # Verbose: Enable logging for interactions with the Kafka cluster.
    Verbose: false

    # TLS: TLS settings for the orderer's connection to the Kafka cluster.
    TLS:

      # Enabled: Use TLS when connecting to the Kafka cluster.
      Enabled: false

      # PrivateKey: PEM-encoded private key the orderer will use for
      # authentication.
      PrivateKey:
        # As an alternative to specifying the PrivateKey here, uncomment the
        # following "File" key and specify the file name from which to load the
        # value of PrivateKey.
        #File: path/to/PrivateKey

      # Certificate: PEM-encoded signed public key certificate the orderer will
      # use for authentication.
      Certificate:
        # As an alternative to specifying the Certificate here, uncomment the
        # following "File" key and specify the file name from which to load the
        # value of Certificate.
        #File: path/to/Certificate

      # RootCAs: PEM-encoded trusted root certificates used to validate
      # certificates from the Kafka cluster.
      RootCAs:
        # As an alternative to specifying the RootCAs here, uncomment the
        # following "File" key and specify the file name from which to load the
        # value of RootCAs.
        #File: path/to/RootCAs

    # SASLPlain: Settings for using SASL/PLAIN authentication with Kafka brokers
    SASLPlain:
      # Enabled: Use SASL/PLAIN to authenticate with Kafka brokers
      Enabled: false
      # User: Required when Enabled is set to true
      User:
      # Password: Required when Enabled is set to true
      Password:

    # Kafka protocol version used to communicate with the Kafka cluster brokers
    # (defaults to 0.10.2.0 if not specified)
    Version:

################################################################################
#
#   Debug Configuration
#
#   - This controls the debugging options for the orderer
#
################################################################################
Debug:

    # BroadcastTraceDir when set will cause each request to the Broadcast service
    # for this orderer to be written to a file in this directory
    BroadcastTraceDir:

    # DeliverTraceDir when set will cause each request to the Deliver service
    # for this orderer to be written to a file in this directory
    DeliverTraceDir:

################################################################################
#
#   Operations Configuration
#
#   - This configures the operations server endpoint for the orderer
#
################################################################################
Operations:
    # host and port for the operations server
    ListenAddress: 127.0.0.1:8443

    # TLS configuration for the operations endpoint
    TLS:
        # TLS enabled
        Enabled: false

        # Certificate is the location of the PEM encoded TLS certificate
        Certificate:

        # PrivateKey points to the location of the PEM-encoded key
        PrivateKey:

        # Most operations service endpoints require client authentication when TLS
        # is enabled. ClientAuthRequired requires client certificate authentication
        # at the TLS layer to access all resources.
        ClientAuthRequired: false

        # Paths to PEM encoded ca certificates to trust for client authentication
        ClientRootCAs: []

################################################################################
#
#   Metrics Configuration
#
#   - This configures metrics collection for the orderer
#
################################################################################
Metrics:
    # The metrics provider is one of statsd, prometheus, or disabled
    Provider: disabled

    # The statsd configuration
    Statsd:
      # network type: tcp or udp
      Network: udp

      # the statsd server address
      Address: 127.0.0.1:8125

      # The interval at which locally cached counters and gauges are pushed
      # to statsd; timings are pushed immediately
      WriteInterval: 30s

      # The prefix is prepended to all emitted statsd metrics
      Prefix:

################################################################################
#
#   Admin Configuration
#
#   - This configures the admin server endpoint for the orderer
#
################################################################################
Admin:
    # host and port for the admin server
    ListenAddress: 127.0.0.1:9443

    # TLS configuration for the admin endpoint
    TLS:
        # TLS enabled
        Enabled: false

        # Certificate is the location of the PEM encoded TLS certificate
        Certificate:

        # PrivateKey points to the location of the PEM-encoded key
        PrivateKey:

        # Most admin service endpoints require client authentication when TLS
        # is enabled. ClientAuthRequired requires client certificate authentication
        # at the TLS layer to access all resources.
        #
        # NOTE: When TLS is enabled, the admin endpoint requires mutual TLS. The
        # orderer will panic on startup if this value is set to false.
        ClientAuthRequired: true

        # Paths to PEM encoded ca certificates to trust for client authentication
        ClientRootCAs: []

################################################################################
#
#   Channel participation API Configuration
#
#   - This provides the channel participation API configuration for the orderer.
#   - Channel participation uses the ListenAddress and TLS settings of the Admin
#     service.
#
################################################################################
ChannelParticipation:
    # Channel participation API is enabled.
    Enabled: false

    # The maximum size of the request body when joining a channel.
    MaxRequestBodySize: 1 MB


################################################################################
#
#   Consensus Configuration
#
#   - This section contains config options for a consensus plugin. It is opaque
#     to orderer, and completely up to consensus implementation to make use of.
#
################################################################################
Consensus:
    # The allowed key-value pairs here depend on consensus plugin. For etcd/raft,
    # we use following options:

    # WALDir specifies the location at which Write Ahead Logs for etcd/raft are
    # stored. Each channel will have its own subdir named after channel ID.
    WALDir: /var/hyperledger/production/orderer/etcdraft/wal

    # SnapDir specifies the location at which snapshots for etcd/raft are
    # stored. Each channel will have its own subdir named after channel ID.
    SnapDir: /var/hyperledger/production/orderer/etcdraft/snapshot


`
)

func EnrollOrdererCertificates(
	ordererInitOptions config.OrdererInitOptions,
	//caConfig *utils.CAConfig,
	//ordererId string,
	//hosts []string,
	//ordererDir string,
) error {
	ordererID := ordererInitOptions.ID
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	ordererDir := filepath.Join(home, fmt.Sprintf("hlf-easy/orderers/%s", ordererID))
	err = os.MkdirAll(ordererDir, 0755)
	if err != nil {
		log.Fatal(err)
	}
	// check if output exists, if it does, return non error
	if !ordererInitOptions.Local {
		return errors.Errorf("not local provisioning is not implemented")
	}
	caConfig, err := utils.GetCAConfig(ordererInitOptions.CAName)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(ordererDir, "orderer.yaml")); err == nil {
		return nil
	}
	var ips []net.IP
	var dnsNames []string
	for _, host := range ordererInitOptions.Hosts {
		// check if it's ip address
		ip := net.ParseIP(host)
		if ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, host)
		}
	}
	// create orderer tls cert
	tlsCert, tlsKey, err := certs.GenerateCertificate(
		certs.GenerateCertificateOptions{
			CommonName:       "orderer",
			OrganizationUnit: []string{"orderer"},
			IPAddresses:      ips,
			DNSNames:         dnsNames,
		},
		caConfig.TLSCACert,
		caConfig.TLSCAKey,
	)
	if err != nil {
		return err
	}

	// create orderer cert
	ordererCert, ordererKey, err := certs.GenerateCertificate(
		certs.GenerateCertificateOptions{
			CommonName:       "orderer",
			OrganizationUnit: []string{"orderer"},
			IPAddresses:      []net.IP{},
			DNSNames:         []string{},
		},
		caConfig.CACert,
		caConfig.CAKey,
	)
	if err != nil {
		return err
	}
	tlsKeyBytes, err := utils.EncodePrivateKey(tlsKey)
	if err != nil {
		return err
	}
	signKeyBytes, err := utils.EncodePrivateKey(ordererKey)
	if err != nil {
		return err
	}

	ordererConfig := config.PeerConfig{
		TLSKey:    tlsKeyBytes,
		TLSCert:   utils.EncodeX509Certificate(tlsCert),
		SignKey:   signKeyBytes,
		SignCert:  utils.EncodeX509Certificate(ordererCert),
		PeerID:    ordererID,
		TlsCACert: utils.EncodeX509Certificate(caConfig.TLSCACert),
		CaCert:    utils.EncodeX509Certificate(caConfig.CACert),
	}
	ordererConfigBytes, err := json.MarshalIndent(ordererConfig, "", "  ")
	if err != nil {
		return err
	}
	ordererConfigFilePath := filepath.Join(ordererDir, "config.json")
	err = os.WriteFile(ordererConfigFilePath, ordererConfigBytes, 0644)
	if err != nil {
		return err
	}

	// keystore key pem
	keyStoreDir := filepath.Join(ordererDir, "keystore")
	err = os.MkdirAll(keyStoreDir, 0755)
	if err != nil {
		return err
	}
	signKeyFilePath := filepath.Join(keyStoreDir, "key.pem")
	err = os.WriteFile(signKeyFilePath, signKeyBytes, 0644)
	if err != nil {
		return err
	}

	// tlscacerts pem
	tlsCACertsDir := filepath.Join(ordererDir, "tlscacerts")
	err = os.MkdirAll(tlsCACertsDir, 0755)
	if err != nil {
		return err
	}
	tlsCACertFilePath := filepath.Join(tlsCACertsDir, "cacert.pem")
	err = os.WriteFile(tlsCACertFilePath, utils.EncodeX509Certificate(caConfig.TLSCACert), 0644)
	if err != nil {
		return err
	}

	// cacerts pem
	cACertsDir := filepath.Join(ordererDir, "cacerts")
	err = os.MkdirAll(cACertsDir, 0755)
	if err != nil {
		return err
	}
	caCertFilePath := filepath.Join(cACertsDir, "cacert.pem")
	err = os.WriteFile(caCertFilePath, utils.EncodeX509Certificate(caConfig.CACert), 0644)
	if err != nil {
		return err
	}

	// signcerts pem
	signCertsDir := filepath.Join(ordererDir, "signcerts")
	err = os.MkdirAll(signCertsDir, 0755)
	if err != nil {
		return err
	}
	signCertFilePath := filepath.Join(signCertsDir, "cert.pem")
	err = os.WriteFile(signCertFilePath, utils.EncodeX509Certificate(ordererCert), 0644)
	if err != nil {
		return err
	}

	// config.yaml
	configFilePath := filepath.Join(ordererDir, "config.yaml")
	configYamlContent := `NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: orderer
  AdminOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/cacert.pem
    OrganizationalUnitIdentifier: orderer
`
	err = os.WriteFile(configFilePath, []byte(configYamlContent), 0644)
	if err != nil {
		return err
	}
	// write tls.key
	tlsKeyFilePath := filepath.Join(ordererDir, "tls.key")
	err = os.WriteFile(tlsKeyFilePath, tlsKeyBytes, 0644)
	if err != nil {
		return err
	}

	// write tls.crt
	tlsCertFilePath := filepath.Join(ordererDir, "tls.crt")
	err = os.WriteFile(tlsCertFilePath, utils.EncodeX509Certificate(tlsCert), 0644)
	if err != nil {
		return err
	}

	// write orderer.yaml based in the template
	tmpl, err := template.New("orderer.yaml").Funcs(sprig.HermeticTxtFuncMap()).Parse(ordererYamlTemplate)
	if err != nil {
		return err
	}
	coreYamlFilePath := filepath.Join(ordererDir, "orderer.yaml")
	coreYamlFile, err := os.Create(coreYamlFilePath)
	if err != nil {
		return err
	}
	defer coreYamlFile.Close()
	err = tmpl.Execute(coreYamlFile, struct {
		FileSystemPath string
	}{
		FileSystemPath: filepath.Join(ordererDir, "data"),
	})
	if err != nil {
		return err
	}
	return nil
}

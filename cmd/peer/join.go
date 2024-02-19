package peer

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/resmgmt"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"hlf-easy/utils"
	"os"
	"text/template"
)

const tmplGoConfig = `
name: hlf-network
version: 1.0.0
client:
  organization: "{{ .Organization }}"
{{- if not .Organizations }}
organizations: {}
{{- else }}
organizations:
  {{ range $org := .Organizations }}
  {{ $org.MSPID }}:
    mspid: {{ $org.MSPID }}
    cryptoPath: /tmp/cryptopath
{{- if not $org.Users }}
    users: {}
{{- else }}
    users:
    {{- range $user := $org.Users }}
      {{ $user.Name }}:
        cert:
          pem: |
{{ $user.Cert | indent 12 }}
        key:
          pem: |
{{ $user.Key | indent 12 }}
    {{- end }}
{{- end }}
{{- if not $org.CertAuths }}
    certificateAuthorities: []
{{- else }}
    certificateAuthorities: 
      {{- range $ca := $org.CertAuths }}
      - {{ $ca.Name }}
 	  {{- end }}
{{- end }}
{{- if not $org.Peers }}
    peers: []
{{- else }}
    peers:
      {{- range $peer := $org.Peers }}
      - {{ $peer }}
 	  {{- end }}
{{- end }}
{{- if not $org.Orderers }}
    orderers: []
{{- else }}
    orderers:
      {{- range $orderer := $org.Orderers }}
      - {{ $orderer }}
 	  {{- end }}

    {{- end }}
{{- end }}
{{- end }}

{{- if not .Orderers }}
{{- else }}
orderers:
{{- range $orderer := .Orderers }}
  {{$orderer.Name}}:
    url: {{ $orderer.URL }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ $orderer.TLSCACert | indent 8 }}
{{- end }}
{{- end }}

{{- if not .Peers }}
{{- else }}
peers:
  {{- range $peer := .Peers }}
  {{$peer.Name}}:
    url: {{ $peer.URL }}
    grpcOptions:
      allow-insecure: false
    tlsCACerts:
      pem: |
{{ $peer.TLSCACert | indent 8 }}
{{- end }}
{{- end }}

{{- if not .CertAuths }}
{{- else }}
certificateAuthorities:
{{- range $ca := .CertAuths }}
  {{ $ca.Name }}:
    url: https://{{ $ca.URL }}
{{if $ca.EnrollID }}
    registrar:
        enrollId: {{ $ca.EnrollID }}
        enrollSecret: "{{ $ca.EnrollSecret }}"
{{ end }}
    caName: {{ $ca.CAName }}
    tlsCACerts:
      pem: 
       - |
{{ $ca.TLSCert | indent 12 }}

{{- end }}
{{- end }}

channels:
  demo:
{{- if not .Orderers }}
    orderers: []
{{- else }}
    orderers:
{{- range $orderer := .Orderers }}
      - {{$orderer.Name}}
{{- end }}
{{- end }}
{{- if not .Peers }}
    peers: {}
{{- else }}
    peers:
{{- range $peer := .Peers }}
       {{$peer.Name}}:
        discover: true
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
{{- end }}
{{- end }}

`

type NetworkConfigResponse struct {
	NetworkConfig string
}

type CA struct {
	Name         string
	URL          string
	EnrollID     string
	EnrollSecret string
	CAName       string
	TLSCert      string
}
type Org struct {
	MSPID     string
	CertAuths []string
	Peers     []string
	Orderers  []string
	Users     []OrgUser
}

type Peer struct {
	Name      string
	URL       string
	TLSCACert string
}

type Orderer struct {
	URL       string
	Name      string
	TLSCACert string
}
type OrgUser struct {
	Name string
	Cert string
	Key  string
}

func GenerateNetworkConfigForFollower(peer *Peer, peerUsers []OrgUser, orderer *Orderer, mspID string) (*NetworkConfigResponse, error) {
	tmpl, err := template.New("networkConfig").Funcs(sprig.HermeticTxtFuncMap()).Parse(tmplGoConfig)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	orgs := []*Org{}
	peers := []*Peer{
		peer,
	}
	var certAuths []*CA
	ordererNodes := []*Orderer{
		orderer,
	}
	org := &Org{
		MSPID:     mspID,
		CertAuths: []string{},
		Peers:     []string{peer.Name},
		Orderers:  []string{},
		Users:     peerUsers,
	}
	orgs = append(orgs, org)
	err = tmpl.Execute(&buf, map[string]interface{}{
		"Peers":         peers,
		"Orderers":      ordererNodes,
		"Organizations": orgs,
		"CertAuths":     certAuths,
		"Organization":  mspID,
		"Internal":      false,
	})
	if err != nil {
		return nil, err
	}
	return &NetworkConfigResponse{
		NetworkConfig: buf.String(),
	}, nil
}

type peerJoinOptions struct {
	ChannelName    string
	Identity       string
	PeerID         string
	OrdererURL     string
	OrdererTLSCert string
}
type peerJoinCmd struct {
	peerOpts peerJoinOptions
}

func (c *peerJoinCmd) validate() error {
	// validate flags here
	if c.peerOpts.ChannelName == "" {
		return errors.Errorf("--channel-name is required")
	}
	if c.peerOpts.PeerID == "" {
		return errors.Errorf("--peer-id is required")
	}
	if c.peerOpts.OrdererURL == "" {
		return errors.Errorf("--orderer-url is required")
	}
	if c.peerOpts.OrdererTLSCert == "" {
		return errors.Errorf("--orderer-tls-cert is required")
	}
	return nil
}

type identity struct {
	Cert Pem `json:"cert"`
	Key  Pem `json:"key"`
}
type Pem struct {
	Pem string
}

func (c *peerJoinCmd) run() error {
	ordererTLSCertBytes, err := os.ReadFile(c.peerOpts.OrdererTLSCert)
	if err != nil {
		return err
	}
	orderer := &Orderer{
		URL:       c.peerOpts.OrdererURL,
		Name:      "orderer",
		TLSCACert: string(ordererTLSCertBytes),
	}
	runConfig, err := utils.GetPeerRunConfig(c.peerOpts.PeerID)
	if err != nil {
		return errors.Wrapf(err, "failed to get run config for peer %s, is the peer running?", c.peerOpts.PeerID)
	}
	peerConfig, err := utils.GetPeerConfig(c.peerOpts.PeerID)
	if err != nil {
		return err
	}
	tlsCertBytes := utils.EncodeX509Certificate(peerConfig.TLSCACert)

	peer := &Peer{
		Name:      c.peerOpts.PeerID,
		URL:       fmt.Sprintf("grpcs://%s", runConfig.Options.ExternalEndpoint),
		TLSCACert: string(tlsCertBytes),
	}
	mspID := runConfig.Options.MSPID
	identityBytes, err := os.ReadFile(c.peerOpts.Identity)
	if err != nil {
		return err
	}
	id := &identity{}
	err = yaml.Unmarshal(identityBytes, id)
	if err != nil {
		return err
	}
	username := "admin"
	users := []OrgUser{
		{
			Name: username,
			Cert: id.Cert.Pem,
			Key:  id.Key.Pem,
		},
	}
	nc, err := GenerateNetworkConfigForFollower(
		peer,
		users,
		orderer,
		mspID,
	)
	if err != nil {
		return err
	}
	log.Infof("Network config: %s", nc.NetworkConfig)
	configBackend := config.FromRaw([]byte(nc.NetworkConfig), "yaml")
	sdk, err := fabsdk.New(configBackend)
	if err != nil {
		return err
	}
	sdkContext := sdk.Context(
		fabsdk.WithUser(username),
		fabsdk.WithOrg(mspID),
	)
	resClient, err := resmgmt.New(sdkContext)
	if err != nil {
		return err
	}
	err = resClient.JoinChannel(c.peerOpts.ChannelName)
	if err != nil {
		return err
	}
	log.Infof("Channel joined: %v", c.peerOpts.ChannelName)
	return nil
}

func newPeerJoinCommand() *cobra.Command {
	c := peerJoinCmd{
		peerOpts: peerJoinOptions{},
	}
	cmd := &cobra.Command{
		Use: "join",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := c.validate(); err != nil {
				return err
			}
			return c.run()
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.peerOpts.PeerID, "id", "", "ID of the peer to join")
	f.StringVar(&c.peerOpts.OrdererURL, "orderer-url", "", "URL of the orderer to join")
	f.StringVar(&c.peerOpts.OrdererTLSCert, "orderer-tls-cert", "", "TLS certificate of the orderer to join")
	f.StringVar(&c.peerOpts.ChannelName, "channel", "", "Name of the channel to join")
	f.StringVar(&c.peerOpts.Identity, "identity", "", "Identity to use to join the channel")
	return cmd
}

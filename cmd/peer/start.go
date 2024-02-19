package peer

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"hlf-easy/api"
	"hlf-easy/config"
	"hlf-easy/node"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func StartPeerNodeCommand(stdout *config.SaveOutputWriter, stderr *config.SaveOutputWriter, opts config.StartPeerOpts) (*exec.Cmd, error) {
	// Define the command and arguments
	cmd := exec.Command("peer", "node", "start")
	// Set environment variables specifically for this command
	cmd.Env = []string{

		fmt.Sprintf("CORE_PEER_MSPCONFIGPATH=%s", opts.MSPConfigPath),
		fmt.Sprintf("FABRIC_CFG_PATH=%s", opts.ConfigPeerPath),
		fmt.Sprintf("CORE_PEER_TLS_ROOTCERT_FILE=%s/tlscacerts/cacert.pem", opts.ConfigPeerPath),
		fmt.Sprintf("CORE_PEER_TLS_KEY_FILE=%s/tls.key", opts.ConfigPeerPath),
		fmt.Sprintf("CORE_PEER_TLS_CLIENTCERT_FILE=%s/tls.crt", opts.ConfigPeerPath),
		fmt.Sprintf("CORE_PEER_TLS_CLIENTKEY_FILE=%s/tls.key", opts.ConfigPeerPath),
		fmt.Sprintf("CORE_PEER_TLS_CERT_FILE=%s/tls.crt", opts.ConfigPeerPath),
		"CORE_PEER_TLS_CLIENTAUTHREQUIRED=false",
		fmt.Sprintf("CORE_PEER_TLS_CLIENTROOTCAS_FILES=%s/tlscacerts/cacert.pem", opts.ConfigPeerPath),

		fmt.Sprintf("CORE_PEER_ADDRESS=%s", opts.ExternalEndpoint),
		fmt.Sprintf("CORE_PEER_GOSSIP_EXTERNALENDPOINT=%s", opts.ExternalEndpoint),
		fmt.Sprintf("CORE_PEER_GOSSIP_ENDPOINT=%s", opts.ExternalEndpoint),

		fmt.Sprintf("CORE_PEER_LISTENADDRESS=%s", opts.ListenAddress),
		fmt.Sprintf("CORE_PEER_CHAINCODELISTENADDRESS=%s", opts.ChaincodeAddress),
		fmt.Sprintf("CORE_PEER_EVENTS_ADDRESS=%s", opts.EventsAddress),

		fmt.Sprintf("CORE_OPERATIONS_LISTENADDRESS=%s", opts.OperationsListenAddress),

		"CORE_PEER_NETWORKID=peer01-nid",
		fmt.Sprintf("CORE_PEER_LOCALMSPID=%s", opts.MSPID),

		fmt.Sprintf("CORE_PEER_ID=%s", opts.ID),

		"CORE_OPERATIONS_TLS_ENABLED=false",
		"CORE_OPERATIONS_TLS_CLIENTAUTHREQUIRED=false",

		"CORE_PEER_GOSSIP_ORGLEADER=true",
		fmt.Sprintf("CORE_PEER_GOSSIP_BOOTSTRAP=%s", opts.ExternalEndpoint),
		"CORE_PEER_PROFILE_ENABLED=true",
		"CORE_PEER_ADDRESSAUTODETECT=false",
		"CORE_LOGGING_GOSSIP=info",

		"FABRIC_LOGGING_SPEC=info",
		"CORE_LOGGING_LEDGER=info",
		"CORE_LOGGING_MSP=info",
		"CORE_PEER_COMMITTER_ENABLED=true",
		"CORE_PEER_DISCOVERY_TOUCHPERIOD=60s",
		"CORE_PEER_GOSSIP_USELEADERELECTION=false",

		"CORE_PEER_DISCOVERY_PERIOD=60s",
		"CORE_METRICS_PROVIDER=prometheus",
		"CORE_LOGGING_CAUTHDSL=info",
		"CORE_LOGGING_POLICIES=info",

		"CORE_LEDGER_STATE_STATEDATABASE=goleveldb",

		"CORE_PEER_TLS_ENABLED=true",
		"CORE_LOGGING_GRPC=info",
		"CORE_LOGGING_PEER=info",
	}
	log.Infof("Envs: %v", cmd.Env)
	// Set the Stdout and Stderr to os.Stdout and os.Stderr
	// so that we can see the command output
	//cmd.Stdout = os.Stdout
	//cmd.Stderr = os.Stderr
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd, nil
}

type peerCmd struct {
	peerOpts config.PeerStartOptions
}

func (c peerCmd) validate() error {
	if c.peerOpts.ID == "" {
		return fmt.Errorf("--id is required")
	}
	return nil
}

func (c peerCmd) run(views embed.FS) error {
	// check if the peer is enrolled, if not, enroll it
	peerID := c.peerOpts.ID
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	peerConfigDir := filepath.Join(home, "hlf-easy", "peers", peerID)
	peerConfigFilePath := filepath.Join(peerConfigDir, "config.json")
	peerConfigFileBytes, err := os.ReadFile(peerConfigFilePath)
	if err != nil {
		return err
	}
	peerConfig := config.PeerConfig{}
	err = json.Unmarshal(peerConfigFileBytes, &peerConfig)
	if err != nil {
		return err
	}

	// save run.json config in order to indicate that the peer is running
	runConfig := config.PeerRunConfig{
		PeerID:  c.peerOpts.ID,
		Options: c.peerOpts,
	}
	runConfigBytes, err := json.Marshal(runConfig)
	if err != nil {
		return err
	}
	runConfigFilePath := filepath.Join(peerConfigDir, "run.json")
	err = os.WriteFile(runConfigFilePath, runConfigBytes, 0644)
	if err != nil {
		return err
	}
	// delete file on exit
	defer os.Remove(runConfigFilePath)
	ca := make(chan os.Signal, 1)
	signal.Notify(ca, os.Interrupt)
	go func() {
		for sig := range ca {
			// sig is a ^C, handle it
			log.Infof("Received %v signal, stopping", sig)
			err = os.Remove(runConfigFilePath)
			if err != nil {
				log.Warnf("Error removing run config file: %v", err)
			}
		}
	}()
	stdOut := &config.SaveOutputWriter{}
	stdErr := &config.SaveOutputWriter{}
	startPeerOpts := config.StartPeerOpts{
		ID:                      c.peerOpts.ID,
		ListenAddress:           c.peerOpts.ListenAddress,
		ChaincodeAddress:        c.peerOpts.ChaincodeAddress,
		EventsAddress:           c.peerOpts.EventsAddress,
		OperationsListenAddress: c.peerOpts.OperationsListenAddress,
		ExternalEndpoint:        c.peerOpts.ExternalEndpoint,
		MSPID:                   c.peerOpts.MSPID,
		MSPConfigPath:           peerConfigDir,
		ConfigPeerPath:          peerConfigDir,
	}
	cmdGetter := func() (*exec.Cmd, error) {
		cmd, err := StartPeerNodeCommand(
			stdOut,
			stdErr,
			startPeerOpts)
		if err != nil {
			log.Warnf("Failed to start peer node: %v", err)
			return nil, err
		}
		return cmd, nil
	}

	peerNode := node.NewPeerNode(
		c.peerOpts.ID,
		c.peerOpts.MSPID,
		cmdGetter,
	)
	go func() {
		if err := peerNode.Start(); err != nil {
			log.Fatalf("Failed to start peer node: %v", err)
		}
		log.Infof("Peer node command finished")
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g, err := api.NewPeerRouter(
		peerNode,
		stdOut,
		stdErr,
		c.peerOpts,
		startPeerOpts,
		views,
	)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    c.peerOpts.ManagementAddress,
		Handler: g,
	}

	go func() {
		// start the admin API server + UI
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Listen for the interrupt signal.
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	log.Infof("shutting down gracefully, press Ctrl+C again to force")

	// The context is used to inform the server it has 5 seconds to finish
	// the request it is currently handling
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return errors.Wrapf(err, "Server forced to shutdown")
	}

	log.Infof("Server exiting")

	return nil
}

// NewPeerCommand creates a new 'peer' Cobra command
func newPeerStartCommand(views embed.FS) *cobra.Command {
	c := peerCmd{
		peerOpts: config.PeerStartOptions{},
	}
	cmd := &cobra.Command{
		Use:   "start",
		Short: "A brief description of the 'peer' command",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your command. For example:

Cobra is a powerful library for creating powerful modern CLI 
applications, and the 'peer' command is a part of this application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Infof("peer command")
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(views)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.peerOpts.ID, "id", "", "ID of the peer")
	f.StringVar(&c.peerOpts.ListenAddress, "listen-address", "0.0.0.0:7051", "Listen address of the peer")
	f.StringVar(&c.peerOpts.ChaincodeAddress, "chaincode-address", "0.0.0.0:7052", "Chaincode address of the peer")
	f.StringVar(&c.peerOpts.EventsAddress, "events-address", "0.0.0.0:7053", "Events address of the peer")
	f.StringVar(&c.peerOpts.OperationsListenAddress, "operations-listen-address", "0.0.0.0:9443", "Operations listen address of the peer")
	f.StringVar(&c.peerOpts.ExternalEndpoint, "external-endpoint", "", "External endpoint of the peer")
	f.StringVar(&c.peerOpts.MSPID, "msp-id", "", "MSP ID of the peer")
	f.StringVar(&c.peerOpts.ManagementAddress, "mgmt-address", "", "Management address of the peer")
	return cmd
}

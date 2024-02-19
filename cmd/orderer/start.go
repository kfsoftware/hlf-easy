package orderer

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
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func StartOrdererNodeCommand(stdout *config.SaveOutputWriter, stderr *config.SaveOutputWriter, opts config.StartOrdererOpts) (*exec.Cmd, error) {
	// Define the command and arguments
	cmd := exec.Command("orderer")
	host, port, err := net.SplitHostPort(opts.ListenAddress)
	if err != nil {
		return nil, err
	}
	// Set environment variables specifically for this command
	cmd.Env = []string{
		fmt.Sprintf("FABRIC_CFG_PATH=%s", opts.ConfigOrdererPath),

		// related to file system
		fmt.Sprintf("ORDERER_ADMIN_TLS_CLIENTROOTCAS=%s/tlscacerts/cacert.pem", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_ADMIN_TLS_PRIVATEKEY=%s/tls.key", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_ADMIN_TLS_CERTIFICATE=%s/tls.crt", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_ADMIN_TLS_ROOTCAS=%s/tlscacerts/cacert.pem", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_FILELEDGER_LOCATION=%s/data", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=%s/tls.crt", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=%s/tls.key", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_CLUSTER_ROOTCAS=%s/tlscacerts/cacert.pem", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_LOCALMSPDIR=%s", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_TLS_CLIENTROOTCAS=%s/tlscacerts/cacert.pem", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_TLS_CERTIFICATE=%s/tls.crt", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_TLS_PRIVATEKEY=%s/tls.key", opts.ConfigOrdererPath),
		fmt.Sprintf("ORDERER_GENERAL_TLS_ROOTCAS=%s/tlscacerts/cacert.pem", opts.ConfigOrdererPath),

		// related to address
		fmt.Sprintf("ORDERER_ADMIN_LISTENADDRESS=%s", opts.AdminListenAddress),
		fmt.Sprintf("ORDERER_GENERAL_LISTENADDRESS=%s", host),
		fmt.Sprintf("ORDERER_OPERATIONS_LISTENADDRESS=%s", opts.OperationsListenAddress),
		// msp ID

		fmt.Sprintf("ORDERER_GENERAL_LOCALMSPID=%s", opts.MSPID),

		// listen port
		fmt.Sprintf("ORDERER_GENERAL_LISTENPORT=%s", port),

		fmt.Sprintf("ORDERER_ADMIN_TLS_ENABLED=%s", "true"),
		fmt.Sprintf("ORDERER_CHANNELPARTICIPATION_ENABLED=%s", "true"),

		fmt.Sprintf("ORDERER_GENERAL_BATCHSIZE_MAXMESSAGECOUNT=%s", "10"),
		fmt.Sprintf("ORDERER_GENERAL_BATCHTIMEOUT=%s", "1s"),
		fmt.Sprintf("ORDERER_GENERAL_BOOTSTRAPMETHOD=%s", "none"),
		fmt.Sprintf("ORDERER_GENERAL_GENESISPROFILE=%s", "initial"),
		fmt.Sprintf("ORDERER_GENERAL_LEDGERTYPE=%s", "file"),
		fmt.Sprintf("FABRIC_LOGGING_SPEC=%s", "info"),
		fmt.Sprintf("ORDERER_GENERAL_MAXWINDOWSIZE=%s", "1000"),
		fmt.Sprintf("ORDERER_GENERAL_ORDERERTYPE=%s", "etcdraft"),
		fmt.Sprintf("ORDERER_GENERAL_TLS_CLIENTAUTHREQUIRED=%s", "false"),
		fmt.Sprintf("ORDERER_GENERAL_TLS_ENABLED=%s", "true"),
		fmt.Sprintf("ORDERER_METRICS_PROVIDER=%s", "prometheus"),
		fmt.Sprintf("ORDERER_OPERATIONS_TLS_ENABLED=%s", "false"),
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

type ordererCmd struct {
	ordererOpts config.OrdererStartOptions
}

func (c ordererCmd) validate() error {
	if c.ordererOpts.ID == "" {
		return fmt.Errorf("--id is required")
	}
	return nil
}

func (c ordererCmd) run(views embed.FS) error {
	// check if the orderer is enrolled, if not, enroll it
	ordererID := c.ordererOpts.ID
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	ordererConfigDir := filepath.Join(home, "hlf-easy", "orderers", ordererID)
	ordererConfigFilePath := filepath.Join(ordererConfigDir, "config.json")
	ordererConfigFileBytes, err := os.ReadFile(ordererConfigFilePath)
	if err != nil {
		return err
	}
	ordererConfig := config.OrdererConfig{}
	err = json.Unmarshal(ordererConfigFileBytes, &ordererConfig)
	if err != nil {
		return err
	}

	// save run.json config in order to indicate that the orderer is running
	runConfig := config.OrdererRunConfig{
		OrdererID: c.ordererOpts.ID,
		Options:   c.ordererOpts,
	}
	runConfigBytes, err := json.Marshal(runConfig)
	if err != nil {
		return err
	}
	runConfigFilePath := filepath.Join(ordererConfigDir, "run.json")
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
	startOrdererOpts := config.StartOrdererOpts{
		ID:                      c.ordererOpts.ID,
		ListenAddress:           c.ordererOpts.ListenAddress,
		OperationsListenAddress: c.ordererOpts.OperationsListenAddress,
		ExternalEndpoint:        c.ordererOpts.ExternalEndpoint,
		MSPID:                   c.ordererOpts.MSPID,
		MSPConfigPath:           ordererConfigDir,
		ConfigOrdererPath:       ordererConfigDir,
	}
	cmdGetter := func() (*exec.Cmd, error) {
		cmd, err := StartOrdererNodeCommand(
			stdOut,
			stdErr,
			startOrdererOpts)
		if err != nil {
			log.Warnf("Failed to start orderer node: %v", err)
			return nil, err
		}
		return cmd, nil
	}

	ordererNode := node.NewOrdererNode(
		c.ordererOpts.ID,
		c.ordererOpts.MSPID,
		cmdGetter,
	)
	go func() {
		if err := ordererNode.Start(); err != nil {
			log.Fatalf("Failed to start orderer node: %v", err)
		}
		log.Infof("Orderer node command finished")
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g, err := api.NewOrdererRouter(
		ordererNode,
		stdOut,
		stdErr,
		c.ordererOpts,
		startOrdererOpts,
		views,
	)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    c.ordererOpts.ManagementAddress,
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

// NewOrdererCommand creates a new 'orderer' Cobra command
func newOrdererStartCommand(views embed.FS) *cobra.Command {
	c := ordererCmd{
		ordererOpts: config.OrdererStartOptions{},
	}
	cmd := &cobra.Command{
		Use:   "start",
		Short: "A brief description of the 'orderer' command",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your command. For example:

Cobra is a powerful library for creating powerful modern CLI 
applications, and the 'orderer' command is a part of this application.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Infof("orderer command")
			if err := c.validate(); err != nil {
				return err
			}
			return c.run(views)
		},
	}
	f := cmd.Flags()
	f.StringVar(&c.ordererOpts.ID, "id", "", "ID of the orderer")
	f.StringVar(&c.ordererOpts.ListenAddress, "listen-address", "0.0.0.0:7051", "Listen address of the orderer")
	f.StringVar(&c.ordererOpts.AdminListenAddress, "admin-listen-address", "0.0.0.0:7053", "Admin listen address of the orderer")
	f.StringVar(&c.ordererOpts.OperationsListenAddress, "operations-listen-address", "0.0.0.0:9443", "Operations listen address of the orderer")
	f.StringVar(&c.ordererOpts.ExternalEndpoint, "external-endpoint", "", "External endpoint of the orderer")
	f.StringVar(&c.ordererOpts.MSPID, "msp-id", "", "MSP ID of the orderer")
	f.StringVar(&c.ordererOpts.ManagementAddress, "mgmt-address", "", "Management address of the orderer")
	return cmd
}

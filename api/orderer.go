package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-lib-go/healthz"
	"github.com/hyperledger/fabric/core/operations"
	"hlf-easy/config"
	"hlf-easy/node"
	"hlf-easy/ui"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

type OrdererClient struct {
	OperationsAddress string
	OrdererAddress    string
}

func (pc *OrdererClient) GetVersionInfo() (*operations.VersionInfoHandler, error) {
	resp, err := http.Get(pc.OperationsAddress + "/version")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	versionInfo := &operations.VersionInfoHandler{}
	err = json.Unmarshal(body, versionInfo)
	if err != nil {
		return nil, err
	}
	return versionInfo, nil
}

func (pc *OrdererClient) GetHealthz() (*healthz.HealthStatus, error) {
	resp, err := http.Get(pc.OperationsAddress + "/healthz")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	healthInfo := &healthz.HealthStatus{}
	err = json.Unmarshal(body, healthInfo)
	if err != nil {
		return nil, err
	}
	return healthInfo, nil
}

func getHandlerFuncForOrdererFile(opts config.StartOrdererOpts, filename string) func(c *gin.Context) {
	return func(c *gin.Context) {
		contents, err := os.ReadFile(filepath.Join(opts.MSPConfigPath, filename))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"contents": string(contents),
		})
	}
}

func NewOrdererRouter(
	node *node.OrdererNode,
	cmdOrdererStdout *config.SaveOutputWriter,
	cmdOrdererStderr *config.SaveOutputWriter,
	startOptions config.OrdererStartOptions,
	opts config.StartOrdererOpts,
	views embed.FS,
) (*gin.Engine, error) {
	r := gin.Default()
	peerClient := &OrdererClient{
		OperationsAddress: fmt.Sprintf("http://%s", startOptions.OperationsListenAddress),
		OrdererAddress:    startOptions.ListenAddress,
	}
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true                                                   // Allow all origins
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} // Specify what methods are allowed
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}

	r.Use(cors.New(config))
	r.GET("/tls.crt", getHandlerFuncForOrdererFile(opts, "tls.crt"))
	r.GET("/tlscacert.crt", getHandlerFuncForOrdererFile(opts, "tlscacerts/cacert.pem"))
	r.GET("/cacert.crt", getHandlerFuncForOrdererFile(opts, "cacerts/cacert.pem"))
	r.GET("/sign.crt", getHandlerFuncForOrdererFile(opts, "signcerts/cert.pem"))
	r.GET("/core.yaml", getHandlerFuncForOrdererFile(opts, "core.yaml"))
	r.POST("/restart", func(context *gin.Context) {
		err := node.Stop()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		err = node.Start()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		context.JSON(http.StatusOK, gin.H{
			"success": true,
		})
	})
	r.POST("/stop", func(context *gin.Context) {
		err := node.Stop()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		context.JSON(http.StatusOK, gin.H{
			"success": true,
		})
	})
	r.POST("/start", func(context *gin.Context) {
		err := node.Start()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		context.JSON(http.StatusOK, gin.H{
			"success": true,
		})
	})
	r.GET("/status", func(context *gin.Context) {
		status, err := node.Status()
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		context.JSON(http.StatusOK, status)
	})
	r.GET("/config", func(c *gin.Context) {
		conf, err := node.GetConfig()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		status, err := node.Status()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		version, err := peerClient.GetVersionInfo()
		if err != nil {
			// return generic error in this gin route
			version = &operations.VersionInfoHandler{
				Version:   "unknown",
				CommitSHA: "unknown",
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"config":       conf,
			"status":       status,
			"version":      version,
			"startOptions": startOptions,
		})
	})
	r.GET("/logs", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"stdout": string(cmdOrdererStdout.GetSavedOutput()),
			"stderr": string(cmdOrdererStderr.GetSavedOutput()),
		})
	})
	fileSystem := ui.NewFileSystemUI(views, "web")

	r.GET("/healthz", func(c *gin.Context) {
		version, err := peerClient.GetHealthz()
		if err != nil {
			// return generic error in this gin route
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, version)
	})

	r.GET("/version", func(c *gin.Context) {
		version, err := peerClient.GetVersionInfo()
		if err != nil {
			// return generic error in this gin route
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, version)
	})
	r.Use(static.Serve("/", fileSystem))
	r.NoRoute(ReturnPublic(views))
	return r, nil
}

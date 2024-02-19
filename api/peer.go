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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

type PeerClient struct {
	OperationsAddress string
	PeerAddress       string
}

func (pc *PeerClient) GetVersionInfo() (*operations.VersionInfoHandler, error) {
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

func (pc *PeerClient) GetHealthz() (*healthz.HealthStatus, error) {
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

func getHandlerFuncForFile(opts config.StartPeerOpts, filename string) func(c *gin.Context) {
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

func NewPeerRouter(
	node *node.PeerNode,
	cmdPeerStdout *config.SaveOutputWriter,
	cmdPeerStderr *config.SaveOutputWriter,
	startOptions config.PeerStartOptions,
	opts config.StartPeerOpts,
	views embed.FS,
) (*gin.Engine, error) {
	r := gin.Default()
	peerClient := &PeerClient{
		OperationsAddress: fmt.Sprintf("http://%s", startOptions.OperationsListenAddress),
		PeerAddress:       startOptions.ListenAddress,
	}
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true                                                   // Allow all origins
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} // Specify what methods are allowed
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type"}

	r.Use(cors.New(config))
	r.GET("/tls.crt", getHandlerFuncForFile(opts, "tls.crt"))
	r.GET("/tlscacert.crt", getHandlerFuncForFile(opts, "tlscacerts/cacert.pem"))
	r.GET("/cacert.crt", getHandlerFuncForFile(opts, "cacerts/cacert.pem"))
	r.GET("/sign.crt", getHandlerFuncForFile(opts, "signcerts/cert.pem"))
	r.GET("/core.yaml", getHandlerFuncForFile(opts, "core.yaml"))
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
			"stdout": string(cmdPeerStdout.GetSavedOutput()),
			"stderr": string(cmdPeerStderr.GetSavedOutput()),
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

func ReturnPublic(views embed.FS) gin.HandlerFunc {
	return func(context *gin.Context) {
		method := context.Request.Method
		if method == "GET" {
			index, err := views.Open("web/index.html")
			if err != nil {
				context.AbortWithStatus(http.StatusNotFound)
				return
			}
			defer index.Close()
			data, err := io.ReadAll(index)
			if err != nil {
				context.AbortWithStatus(http.StatusNotFound)
				return
			}
			context.Data(http.StatusOK, "text/html; charset=utf-8", data)
		} else {
			context.Next()
		}
	}
}

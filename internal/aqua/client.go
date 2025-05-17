package aqua

import (
	"net/http"
	"time"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Client struct {
	client *http.Client
}

func NewClient() *Client {
	return &Client{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Cleanup() {
	if c.client != nil {
		log.Debug("Closing idle connections")
		c.client.CloseIdleConnections()
	}
}

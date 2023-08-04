package elasticsearch

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"supportmafia/server/config"

	"github.com/opensearch-project/opensearch-go"
)

type ElasticSearch struct {
	Client *opensearch.Client
}

func NewESConnection(c *config.ESConfig) *ElasticSearch {
	cfg := opensearch.Config{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Addresses: []string{c.Host},
		Username:  c.Username,
		Password:  c.Password,
	}
	es, err := opensearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("failed to establish connection with elasticsearch: %s", err)
		os.Exit(1)
	}

	res, err := es.Info()
	if err != nil {
		log.Fatalf("Error getting response from elasticsearch: %s", err)
		os.Exit(1)
	}
	if res.IsError() {
		log.Fatalf("Error getting response from elasticsearch: %s", res)
		os.Exit(1)
	}
	defer res.Body.Close()

	return &ElasticSearch{Client: es}
}

func (e *ElasticSearch) Conn() *opensearch.Client {
	return e.Client
}

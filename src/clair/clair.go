package clair

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/docker/distribution/manifest/schema2"
	"github.com/go-resty/resty/v2"
	"github.com/indece-official/clair-client/src/docker"
	"github.com/indece-official/clair-client/src/generated/model/apiclair"
)

const IndexStatusFinished = "IndexFinished"

var (
	flagClairUrl      = flag.String("clair-url", "", "Clair URL")
	flagClairUsername = flag.String("clair-username", "", "Clair username")
	flagClairPassword = flag.String("clair-password", "", "Clair password")
)

type ClairClient struct {
	client *resty.Client
}

func (c *ClairClient) Connect() error {
	c.client = resty.New()

	return nil
}

func (c *ClairClient) createRequest() *resty.Request {
	req := c.client.R()

	if *flagClairUsername != "" && *flagClairPassword != "" {
		req = req.SetBasicAuth(*flagClairUsername, *flagClairPassword)
	}

	return req
}

func (c *ClairClient) IndexManifest(
	manifest *schema2.DeserializedManifest,
	imageIdentifiers *docker.ImageIdentifiers,
	dockerRegistry string,
	dockerAuthToken string,
) (string, error) {
	url := fmt.Sprintf("%s/indexer/api/v1/index_report", *flagClairUrl)

	requestBody := &apiclair.IndexJSONRequestBody{}
	requestBody.Hash = apiclair.Digest(manifest.Config.Digest)
	requestBody.Layers = []apiclair.Layer{}

	for _, manifestLayer := range manifest.Layers {
		requestLayer := apiclair.Layer{}

		requestLayer.Hash = apiclair.Digest(manifestLayer.Digest)
		uri := ""

		if len(manifestLayer.URLs) <= 0 {
			uri = fmt.Sprintf(
				"%s/v2/%s/blobs/%s",
				dockerRegistry,
				imageIdentifiers.Repository,
				manifestLayer.Digest,
			)
		} else {
			uri = manifestLayer.URLs[0]
		}

		requestLayer.Uri = uri
		requestLayer.Headers = apiclair.Layer_Headers{}
		requestLayer.Headers.AdditionalProperties = map[string][]string{}

		if dockerAuthToken != "" {
			requestLayer.Headers.AdditionalProperties["Authorization"] = []string{
				dockerAuthToken,
			}
		}

		requestBody.Layers = append(requestBody.Layers, requestLayer)
	}

	resp, err := c.createRequest().
		SetBody(requestBody).
		Post(url)
	if err != nil {
		return "", fmt.Errorf("can't index manifest in clair: %s", err)
	}

	if !resp.IsSuccess() {
		return "", fmt.Errorf("can't index manifest in clair: %d %s - %s", resp.StatusCode(), resp.Status(), resp.Body())
	}

	responseBody := &apiclair.IndexReport{}

	err = json.Unmarshal(resp.Body(), responseBody)
	if err != nil {
		return "", fmt.Errorf("can't decode clair index manifest response body: %s", err)
	}

	if responseBody.Err != "" {
		return "", fmt.Errorf("indexing manifest in clair failed: %s", responseBody.Err)
	}

	return responseBody.State, nil
}

func (c *ClairClient) GetIndexManifestStatus(hash string) (string, error) {
	url := fmt.Sprintf("%s/indexer/api/v1/index_report/%s", *flagClairUrl, hash)
	resp, err := c.createRequest().
		Get(url)
	if err != nil {
		return "", fmt.Errorf("can't get index manifest status from clair: %s", err)
	}

	if !resp.IsSuccess() {
		return "", fmt.Errorf("can't get index manifest status from clair: %d %s - %s", resp.StatusCode(), resp.Status(), resp.Body())
	}

	responseBody := &apiclair.IndexReport{}

	err = json.Unmarshal(resp.Body(), responseBody)
	if err != nil {
		return "", fmt.Errorf("can't decode clair index manifest status response body: %s", err)
	}

	if responseBody.Err != "" {
		return "", fmt.Errorf("indexing manifest in clair failed: %s", responseBody.Err)
	}

	return responseBody.State, nil
}

func (c *ClairClient) GetVulnerabilityReport(hash string) (*apiclair.VulnerabilityReport, error) {
	url := fmt.Sprintf("%s/matcher/api/v1/vulnerability_report/%s", *flagClairUrl, hash)
	resp, err := c.createRequest().
		Get(url)
	if err != nil {
		return nil, fmt.Errorf("can't get vulnerability report from clair: %s", err)
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("can't get vulnerability report from clair: %d %s - %s", resp.StatusCode(), resp.Status(), resp.Body())
	}

	responseBody := &apiclair.VulnerabilityReport{}

	err = json.Unmarshal(resp.Body(), responseBody)
	if err != nil {
		return nil, fmt.Errorf("can't decode clair vulnerability report response body: %s", err)
	}

	return responseBody, err
}

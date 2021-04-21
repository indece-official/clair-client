package docker

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/docker/distribution/manifest/schema2"
	"github.com/heroku/docker-registry-client/registry"
)

type ImageIdentifiers struct {
	Repository string
	Tag        string
}

var RegexpProtocol = regexp.MustCompile("^(http[s]?://)")
var RegexpDoubleSlash = regexp.MustCompile("/{2,}")

func parseBearer(bearer string) map[string]string {
	out := make(map[string]string)

	for _, s := range strings.Split(bearer, " ") {
		if s == "Bearer" {
			continue
		}
		for _, params := range strings.Split(s, ",") {
			fields := strings.Split(params, "=")
			if len(fields) < 2 || fields[0] == "" {
				continue
			}

			key := fields[0]
			val := strings.Replace(fields[1], "\"", "", -1)

			out[key] = val
		}
	}
	return out
}

func ParseImageIdentifiers(dockerImagePath string, registryDomain string) (*ImageIdentifiers, error) {
	registryDomain = strings.ToLower(registryDomain)
	registryDomain = RegexpProtocol.ReplaceAllString(registryDomain, "")
	registryDomain = strings.TrimRight(registryDomain, "/")

	dockerImagePath = strings.ToLower(dockerImagePath)
	dockerImagePath = RegexpProtocol.ReplaceAllString(dockerImagePath, "")
	dockerImagePath = RegexpDoubleSlash.ReplaceAllString(dockerImagePath, "/")

	if strings.HasPrefix(dockerImagePath, registryDomain) {
		// Remove Domain
		dockerImagePath = strings.Replace(dockerImagePath, registryDomain, "", 1)
	}

	dockerImagePathParts := strings.SplitN(dockerImagePath, ":", 2)
	repository := ""
	tag := ""

	switch len(dockerImagePathParts) {
	case 1:
		repository = dockerImagePathParts[0]
		tag = "latest"
	case 2:
		repository = dockerImagePathParts[0]
		tag = dockerImagePathParts[1]
	default:
		return nil, fmt.Errorf("invalid docker image path")
	}

	return &ImageIdentifiers{
		Repository: strings.Trim(repository, "/"),
		Tag:        tag,
	}, nil
}

var (
	flagDockerRegistry = flag.String("docker-registry", "", "Docker Registry")
	flagDockerUsername = flag.String("docker-username", "", "Docker registry username")
	flagDockerPassword = flag.String("docker-password", "", "Docker registry password")
)

type DockerClient struct {
	registry *registry.Registry
}

func (d *DockerClient) GetRegistry() string {
	return *flagDockerRegistry
}

func (d *DockerClient) GetUsername() string {
	return *flagDockerUsername
}

func (d *DockerClient) GetPassword() string {
	return *flagDockerPassword
}

func (d *DockerClient) Connect() error {
	url := strings.TrimSuffix(*flagDockerRegistry, "/")
	transport := registry.WrapTransport(http.DefaultTransport, url, *flagDockerUsername, *flagDockerPassword)
	d.registry = &registry.Registry{
		URL: url,
		Client: &http.Client{
			Transport: transport,
		},
		Logf: registry.Quiet,
	}

	err := d.registry.Ping()
	if err != nil {
		return fmt.Errorf("can't connect to docker registry '%s': %s", *flagDockerRegistry, err)
	}

	return nil
}

func (d *DockerClient) GetManifestV2(imageIdentifiers *ImageIdentifiers) (*schema2.DeserializedManifest, error) {
	manifest, err := d.registry.ManifestV2(imageIdentifiers.Repository, imageIdentifiers.Tag)
	if err != nil {
		return nil, fmt.Errorf("error retriving docker manifest v2: %s", err)
	}

	return manifest, nil
}

func (d *DockerClient) GetAuthToken() (string, error) {
	urlReq := fmt.Sprintf("%s/v2/", d.registry.URL)

	// First step is to get the endpoint where we'll be authenticating
	resp, err := http.DefaultClient.Get(urlReq)
	if err != nil {
		return "", fmt.Errorf("docker auth request failed: %s", err)
	}

	// This has the various things we'll need to parse and use in the request
	wwwAuthenticate := resp.Header.Get("Www-Authenticate")
	if wwwAuthenticate == "" {
		// No authentication required

		return "", nil
	}

	if strings.HasPrefix(strings.ToUpper(wwwAuthenticate), "BASIC") {
		credentials := fmt.Sprintf("%s:%s", *flagDockerUsername, *flagDockerPassword)
		credentialsBase64 := base64.StdEncoding.EncodeToString([]byte(credentials))

		return fmt.Sprintf("Basic %s", credentialsBase64), nil
	} else if strings.HasPrefix(strings.ToUpper(wwwAuthenticate), "BEARER") {
		params := parseBearer(wwwAuthenticate)

		// Get the token
		urlRealmStr := fmt.Sprintf("%s?", params["realm"])
		for key, value := range params {
			urlRealmStr += fmt.Sprintf("%s=%s&", key, value)
		}
		urlRealm, err := url.Parse(urlRealmStr)
		if err != nil {
			return "", fmt.Errorf("can't prepare url for docker auth request: %s", err)
		}

		req := &http.Request{
			Method: "GET",
			URL:    urlRealm,
		}
		if *flagDockerUsername != "" && *flagDockerPassword != "" {
			credentials := fmt.Sprintf("%s:%s", *flagDockerUsername, *flagDockerPassword)
			credentialsBase64 := base64.StdEncoding.EncodeToString([]byte(credentials))
			req.Header.Set("Authorization", fmt.Sprintf("Basic %s", credentialsBase64))
		}
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("docker auth realm request failed: %s", err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("can't read auth realm response: %s", err)
		}

		bodyJSON := map[string]interface{}{}
		err = json.Unmarshal(body, &bodyJSON)
		if err != nil {
			return "", fmt.Errorf("can't decode auth realm response: %s", err)
		}

		tokenObj, ok := bodyJSON["token"]
		if !ok {
			return "", fmt.Errorf("missing token in auth realm response")
		}

		token, ok := tokenObj.(string)
		if !ok {
			return "", fmt.Errorf("invalid token in auth realm response")
		}

		return fmt.Sprintf("Bearer %s", token), nil
	} else {
		return "", fmt.Errorf("unsupported auth method %s", wwwAuthenticate)
	}
}

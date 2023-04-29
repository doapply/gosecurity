package installer

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"runtime"

	"github.com/doapply/gosecurity/v2/pkg/catalog/config"
	"github.com/projectdiscovery/retryablehttp-go"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	pdtmGosecurityVersionEndpoint    = "https://api.pdtm.sh/api/v1/tools/gosecurity"
	pdtmGosecurityIgnoreFileEndpoint = "https://api.pdtm.sh/api/v1/tools/gosecurity/ignore"
)

// defaultHttpClient is http client that is only meant to be used for version check
// if proxy env variables are set those are reflected in this client
var retryableHttpClient = retryablehttp.NewClient(retryablehttp.Options{HttpClient: updateutils.DefaultHttpClient, RetryMax: 2})

// PdtmAPIResponse is the response from pdtm API for gosecurity endpoint
type PdtmAPIResponse struct {
	IgnoreHash string `json:"ignore-hash"`
	Tools      []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tools"`
}

// GosecurityVersionCheck checks for the latest version of gosecurity and gosecurity templates
// and returns an error if it fails to check on success it returns nil and changes are
// made to the default config in config.DefaultConfig
func GosecurityVersionCheck() error {
	resp, err := retryableHttpClient.Get(pdtmGosecurityVersionEndpoint + "?" + getpdtmParams())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var pdtmResp PdtmAPIResponse
	if err := json.Unmarshal(bin, &pdtmResp); err != nil {
		return err
	}
	var gosecurityversion, templateversion string
	for _, tool := range pdtmResp.Tools {
		switch tool.Name {
		case "gosecurity":
			if tool.Version != "" {
				gosecurityversion = "v" + tool.Version
			}

		case "gosecurity-templates":
			if tool.Version != "" {
				templateversion = "v" + tool.Version
			}
		}
	}
	return config.DefaultConfig.WriteVersionCheckData(pdtmResp.IgnoreHash, gosecurityversion, templateversion)
}

// getpdtmParams returns encoded query parameters sent to update check endpoint
func getpdtmParams() string {
	params := &url.Values{}
	params.Add("os", runtime.GOOS)
	params.Add("arch", runtime.GOARCH)
	params.Add("go_version", runtime.Version())
	params.Add("v", config.Version)
	return params.Encode()
}

// UpdateIgnoreFile updates default ignore file by downloading latest ignore file
func UpdateIgnoreFile() error {
	resp, err := retryableHttpClient.Get(pdtmGosecurityIgnoreFileEndpoint + "?" + getpdtmParams())
	if err != nil {
		return err
	}
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(config.DefaultConfig.GetIgnoreFilePath(), bin, 0644); err != nil {
		return err
	}
	return config.DefaultConfig.UpdateGosecurityIgnoreHash()
}

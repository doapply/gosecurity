package installer

import (
	"testing"

	"github.com/projectdiscovery/gosecurity/v2/pkg/catalog/config"
	"github.com/projectdiscovery/utils/generic"
	"github.com/stretchr/testify/require"
)

func TestVersionCheck(t *testing.T) {
	err := GosecurityVersionCheck()
	require.Nil(t, err)
	cfg := config.DefaultConfig
	if generic.EqualsAny("", cfg.LatestGosecurityIgnoreHash, cfg.LatestGosecurityVersion, cfg.LatestGosecurityTemplatesVersion) {
		// all above values cannot be empty
		t.Errorf("something went wrong got empty response gosecurity-version=%v templates-version=%v ignore-hash=%v", cfg.LatestGosecurityVersion, cfg.LatestGosecurityTemplatesVersion, cfg.LatestGosecurityIgnoreHash)
	}
}

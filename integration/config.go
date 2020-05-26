package integration

import (
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type Config struct {
	context *cli.Context
	logger  *zap.SugaredLogger

	Quiet      bool
	NoProgress bool
	Debug      bool

	CacheDir       string
	Reset          bool
	DownloadDBOnly bool
	SkipUpdate     bool
	ClearCache     bool

	Input    string
	output   string
	Format   string
	Template string

	Timeout         time.Duration
	ScanRemovedPkgs bool
	vulnType        string
	Light           bool
	severities      string
	IgnoreFile      string
	IgnoreUnfixed   bool
	ExitCode        int

	// these variables are generated by Init()
	ImageName  string
	VulnType   []string
	Output     *os.File
	Severities []dbTypes.Severity
	AppVersion string

	// deprecated
	onlyUpdate string
	// deprecated
	refresh bool
	// deprecated
	autoRefresh bool
}

func NewDbConfig(dir string) (Config, error) {
	logger, err := log.NewLogger(true, true)
	if err != nil {
		return Config{}, xerrors.New("failed to create a logger")
	}
	return Config{
		logger:         logger,
		Debug:          true,
		CacheDir:       dir,
		Reset:          false,
		DownloadDBOnly: true,
	}, nil
}
func NewConfig() (Config, error) {
	logger, err := log.NewLogger(true, true)
	if err != nil {
		return Config{}, xerrors.New("failed to create a logger")
	}
	return Config{
		logger:         logger,
		Debug:          true,
		CacheDir:       "/tmp/zot",
		Reset:          false,
		DownloadDBOnly: true,
		SkipUpdate:     false,
		ClearCache:     false,
		Format:         "table",
		severities:     strings.Join(dbTypes.SeverityNames, ","),
		vulnType:       "os,library",
	}, nil
}

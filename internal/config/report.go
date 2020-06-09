package config

import (
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

type ReportConfig struct {
	Format   string
	Template string

	IgnoreFile    string
	IgnoreUnfixed bool
	ExitCode      int
	IgnorePolicy  string

	// these variables are not exported
	vulnType   string
	output     string
	severities string

	// these variables are populated by Init()
	VulnType   []string
	Output     *os.File
	Severities []dbTypes.Severity
}

func NewReportConfig(c *cli.Context) ReportConfig {
	return ReportConfig{
		output:       c.String("output"),
		Format:       c.String("format"),
		Template:     c.String("template"),
		IgnorePolicy: c.String("ignore-policy"),

		vulnType:      c.String("vuln-type"),
		severities:    c.String("severity"),
		IgnoreFile:    c.String("ignorefile"),
		IgnoreUnfixed: c.Bool("ignore-unfixed"),
		ExitCode:      c.Int("exit-code"),
	}
}

func NewTrivyReportConfig() ReportConfig {
	return ReportConfig{
		Format:     "table",
		severities: strings.Join(dbTypes.SeverityNames, ","),
		vulnType:   "os,library",
	}
}
func (c *ReportConfig) Init(logger *zap.SugaredLogger) (err error) {
	c.Severities = c.splitSeverity(logger, c.severities)
	c.VulnType = strings.Split(c.vulnType, ",")

	// for testability
	c.severities = ""
	c.vulnType = ""

	c.Output = os.Stdout
	if c.output != "" {
		if c.Output, err = os.Create(c.output); err != nil {
			return xerrors.Errorf("failed to create an output file: %w", err)
		}
	}

	return nil
}

func (c *ReportConfig) splitSeverity(logger *zap.SugaredLogger, severity string) []dbTypes.Severity {
	logger.Debugf("Severities: %s", severity)
	var severities []dbTypes.Severity
	for _, s := range strings.Split(severity, ",") {
		severity, err := dbTypes.NewSeverity(s)
		if err != nil {
			logger.Warnf("unknown severity option: %s", err)
		}
		severities = append(severities, severity)
	}
	return severities
}

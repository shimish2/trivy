package integration

import (
	artifact "github.com/aquasecurity/trivy/internal/artifact"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/pkg/report"
)

func ScanTrivyImage(c config.Config) (report.Results, error) {
	return artifact.TrivyImage(c)
}

func RunTrivyDb(c config.Config) error {
	return artifact.RunDb(c)
}

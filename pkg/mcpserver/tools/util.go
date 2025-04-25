package tools

import (
	"os/exec"

	"github.com/aquasecurity/trivy/pkg/log"
)

func findTrivyBinary(trivyBinary string) (string, error) {
	if trivyBinary != "" {
		log.Debug("Using Trivy binary", log.String("trivyBinary", trivyBinary))
		// Check if the provided path is a valid executable
		return trivyBinary, nil
	}

	path, err := exec.LookPath("trivy")
	if err != nil {
		return "", err
	}

	return path, nil
}

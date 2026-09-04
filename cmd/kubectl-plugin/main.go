package main

import (
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/kubewarden/runtime-enforcer/internal/kubectlplugin"
)

func main() {
	cmd := kubectlplugin.NewRootCmd()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

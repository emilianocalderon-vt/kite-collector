//go:build !windows && !darwin

package dashboard

import (
	"context"
	"os/exec"
)

func openBrowser(url string) {
	// xdg-open is the standard on Linux.
	_ = exec.CommandContext(context.Background(), "xdg-open", url).Start() //#nosec G204 -- url is from trusted internal code
}

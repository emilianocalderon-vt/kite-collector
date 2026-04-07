//go:build darwin

package dashboard

import (
	"context"
	"os/exec"
)

func openBrowser(url string) {
	_ = exec.CommandContext(context.Background(), "open", url).Start() //#nosec G204 -- url is from trusted internal code
}

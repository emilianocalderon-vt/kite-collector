//go:build windows

package dashboard

import (
	"context"
	"os/exec"
)

func openBrowser(url string) {
	_ = exec.CommandContext(context.Background(), "cmd", "/c", "start", url).Start() //#nosec G204 -- url is from trusted internal code
}

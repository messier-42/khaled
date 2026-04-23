package keyserver

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// defaultVersionString produces a version string of the form
// "khaled/<version> go/<goversion> <GOOS>/<GOARCH>".
func defaultVersionString() string {
	khaledVersion := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			khaledVersion = info.Main.Version
		}
	}
	return fmt.Sprintf("khaled/%s go/%s %s/%s",
		khaledVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

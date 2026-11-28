//go:build linux

package probes

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestHTTP3PeerPathsResolveFromABuildIDDebugFile(t *testing.T) {
	const pid = 4287
	id := []byte{0x42, 0x87, 0x00, 0x01}
	root := strippedProcess(t, pid, id, false)
	var b dwarfBuilder
	quicServerDWARF(&b, false)
	writeTestELF(t, filepath.Join(root, "usr/lib/debug/.build-id/42/870001.debug"), []testSection{
		{name: ".note.gnu.build-id", typ: shtNote, data: buildIDNote(id)},
		{name: ".debug_abbrev", typ: shtProgbits, data: dwarfAbbreviations()},
		{name: ".debug_info", typ: shtProgbits, data: b.info()},
	})
	paths, ok := resolveH3PeerPaths(filepath.Join(config.ProcBasePath, fmt.Sprint(pid), "exe"), pid, "")
	if !ok || paths.Server.NSteps != 3 {
		t.Fatalf("resolveH3PeerPaths = (%+v, %v), want the server path from the debug file", paths.Server, ok)
	}
}

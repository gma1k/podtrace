package main

import (
	"io"
	"os"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/kubernetes/nodespawn"
	"github.com/gma1k/podtrace/internal/logger"
)

// awaitSpawnAttach holds a spawned podtrace until the CLI that created it
// is attached, so the first lines it writes (target resolution, skipped
// targets, warnings) reach the user instead of being written before
// anyone listens.
func awaitSpawnAttach(stdin io.Reader) {
	if os.Getenv(nodespawn.EnvNodeLocalSentinel) != "1" || os.Getenv(nodespawn.EnvAttachHandshake) != "1" {
		return
	}
	if !nodespawn.AwaitAttachHandshake(stdin, nodespawn.AttachHandshakeTimeout) {
		logger.Warn("The podtrace CLI did not attach in time; continuing. Output written before it attaches is only in the pod log.",
			zap.Duration("waited", nodespawn.AttachHandshakeTimeout))
	}
}

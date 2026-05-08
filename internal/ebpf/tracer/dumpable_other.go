//go:build !linux

package tracer

func setDumpable() error {
	return nil
}
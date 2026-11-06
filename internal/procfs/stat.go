package procfs

import (
	"errors"
	"strconv"
	"strings"
)

// ProcessStat holds the /proc/<pid>/stat fields podtrace reads.
type ProcessStat struct {
	Comm        string
	UserTicks   uint64
	SystemTicks uint64
	StartTicks  uint64
}

var errMalformedStat = errors.New("procfs: malformed stat")

// StatComm returns the command name in /proc/<pid>/stat contents, which is
// readable even where the numeric fields that follow are cut short.
func StatComm(data []byte) (string, bool) {
	s := string(data)
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end <= open {
		return "", false
	}
	return s[open+1 : end], true
}

// ParseProcessStat parses the contents of /proc/<pid>/stat. The command name
// may contain spaces and parentheses, so fields are counted from the last
// closing parenthesis.
func ParseProcessStat(data []byte) (ProcessStat, error) {
	s := string(data)
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open {
		return ProcessStat{}, errMalformedStat
	}
	fields := strings.Fields(s[end+1:])
	if len(fields) < 20 {
		return ProcessStat{}, errMalformedStat
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return ProcessStat{}, errMalformedStat
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return ProcessStat{}, errMalformedStat
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return ProcessStat{}, errMalformedStat
	}
	return ProcessStat{
		Comm:        s[open+1 : end],
		UserTicks:   utime,
		SystemTicks: stime,
		StartTicks:  start,
	}, nil
}

// ReadProcessStat reads and parses /proc/<pid>/stat.
func ReadProcessStat(pid uint32) (ProcessStat, error) {
	data, err := ReadFile(strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return ProcessStat{}, err
	}
	return ParseProcessStat(data)
}

// StartTicks reports when the process now holding pid started, in clock
// ticks after boot.
func StartTicks(pid uint32) (uint64, bool) {
	st, err := ReadProcessStat(pid)
	if err != nil {
		return 0, false
	}
	return st.StartTicks, true
}

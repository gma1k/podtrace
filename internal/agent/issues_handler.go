package agent

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gma1k/podtrace/internal/inspect"
)

// ActiveIssue is one firing issue as /issues reports it: as the latest
// evaluation saw it, with the time it activated.
type ActiveIssue struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"`
	Namespace string    `json:"namespace"`
	Workload  string    `json:"workload"`
	Pod       string    `json:"pod,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	Since     time.Time `json:"since"`
	Message   string    `json:"message"`
}

// issuesHandler serves the engine's active issues as JSON.
func issuesHandler(engine *inspect.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if engine == nil {
			http.Error(w, "continuous inspections are off on this agent", http.StatusNotFound)
			return
		}
		active := engine.ActiveIssues()
		out := struct {
			Issues []ActiveIssue `json:"issues"`
		}{Issues: make([]ActiveIssue, 0, len(active))}
		for _, a := range active {
			out.Issues = append(out.Issues, ActiveIssue{
				ID:        string(a.ID),
				Severity:  string(a.Severity),
				Namespace: a.Subject.Namespace,
				Workload:  a.Subject.Workload,
				Pod:       a.Subject.Pod,
				Resource:  a.Subject.Resource,
				Since:     a.Since,
				Message:   a.Message,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

package report

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/minhhieu21193/cloudaudit/internal/checks"
)

//go:embed templates/report.html.tmpl
var htmlTemplate string

// findingItem is the argument to the "finding" sub-template.
type findingItem struct {
	Prefix string
	N      int
	F      checks.Finding
}

var htmlTmpl = template.Must(template.New("html").Funcs(template.FuncMap{
	"usd":      usd,
	"date":     func(t time.Time) string { return t.Format("2006-01-02 15:04 UTC") },
	"join":     strings.Join,
	"inc":      func(i int) int { return i + 1 },
	"lower":    strings.ToLower,
	"sevClass": func(s checks.Severity) string { return strings.ToLower(s.String()) },
	"item":     func(prefix string, n int, f checks.Finding) findingItem { return findingItem{prefix, n, f} },
}).Parse(htmlTemplate))

// WriteHTML renders a single self-contained HTML file: inline CSS, no
// scripts, no external assets. html/template escapes every value.
func WriteHTML(w io.Writer, r Report) error {
	return htmlTmpl.Execute(w, r)
}

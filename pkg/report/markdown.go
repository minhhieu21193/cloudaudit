package report

import (
	_ "embed"
	"io"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/report.md.tmpl
var markdownTemplate string

var markdownTmpl = template.Must(template.New("md").Funcs(template.FuncMap{
	"usd":  usd,
	"cell": mdCell,
	"date": func(t time.Time) string { return t.Format("2006-01-02 15:04 UTC") },
	"join": strings.Join,
	"inc":  func(i int) int { return i + 1 },
	"code": mdCode,
}).Parse(markdownTemplate))

func WriteMarkdown(w io.Writer, r Report) error {
	return markdownTmpl.Execute(w, r)
}

// mdCell makes a value safe inside a Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

// mdCode renders inline code even when the value contains backticks.
func mdCode(s string) string {
	if strings.Contains(s, "`") {
		return "`` " + s + " ``"
	}
	return "`" + s + "`"
}

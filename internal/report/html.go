package report

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"strings"

	"github.com/Shadow-Security-official/Shadow-Armor/internal/model"
)

//go:embed assets/report.html assets/style.css assets/score.js assets/app.js
var assets embed.FS

// ScoreJS is the JavaScript twin of the Go scoring formula.
func ScoreJS() string {
	b, _ := assets.ReadFile("assets/score.js")
	return string(b)
}

// HTML writes a single self-contained page: no external resource, no CDN,
// strict Content-Security-Policy, works offline and from a mail attachment.
func HTML(w io.Writer, r *model.Report) error {
	page, _ := assets.ReadFile("assets/report.html")
	css, _ := assets.ReadFile("assets/style.css")
	app, _ := assets.ReadFile("assets/app.js")
	// encoding/json escapes <, > and & as unicode escapes, so the data cannot close
	// the <script> element it lives in.
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// Hash-based CSP: only these exact inline blocks may run or apply.
	csp := "default-src 'none'; img-src data:; style-src " + hash(css) + "; script-src " + hash([]byte(ScoreJS())) + " " + hash(app)
	out := strings.NewReplacer(
		"{{CSP}}", csp,
		"{{TITLE}}", html.EscapeString("Shadow-Armor · "+r.Target.URI),
		"{{CSS}}", string(css),
		"{{DATA}}", string(data),
		"{{SCORE}}", ScoreJS(),
		"{{APP}}", string(app),
	).Replace(string(page))
	_, err = io.WriteString(w, out)
	return err
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

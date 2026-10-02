package ui

// Shadow-Armor palette: a violet-to-cyan "shadow to steel" gradient for the
// brand, one colour per grade and per severity.
var (
	Violet = Hex("#8B5CF6")
	Indigo = Hex("#6366F1")
	Blue   = Hex("#3B82F6")
	Cyan   = Hex("#22D3EE")
	Teal   = Hex("#2DD4BF")
	Steel  = Hex("#94A3B8")
	Muted  = Hex("#64748B")
	Faint  = Hex("#475569")
	Ink    = Hex("#E2E8F0")
	White  = Hex("#F8FAFC")

	Green  = Hex("#22C55E")
	Lime   = Hex("#84CC16")
	Amber  = Hex("#F59E0B")
	Orange = Hex("#F97316")
	Red    = Hex("#EF4444")
	Rose   = Hex("#F43F5E")
	Pink   = Hex("#EC4899")
	Sky    = Hex("#38BDF8")
	Purple = Hex("#A855F7")

	// Brand is the logo gradient.
	Brand = []RGB{Hex("#A78BFA"), Violet, Indigo, Blue, Hex("#06B6D4"), Cyan}
	// Heat runs from failing to passing, for score bars.
	Heat = []RGB{Red, Orange, Amber, Lime, Green}
)

// GradeColor is the colour of a letter grade.
func GradeColor(g string) RGB {
	switch g {
	case "A":
		return Green
	case "B":
		return Teal
	case "C":
		return Amber
	case "D":
		return Orange
	case "E":
		return Red
	}
	return Steel
}

// GradeWord says what a grade means.
func GradeWord(g string) string {
	switch g {
	case "A":
		return "Excellent"
	case "B":
		return "Good"
	case "C":
		return "Fair"
	case "D":
		return "Poor"
	case "E":
		return "Critical"
	}
	return "Not graded"
}

// SeverityColor is the colour of a control severity.
func SeverityColor(s string) RGB {
	switch s {
	case "critical":
		return Pink
	case "high":
		return Red
	case "medium":
		return Amber
	case "low":
		return Sky
	}
	return Steel
}

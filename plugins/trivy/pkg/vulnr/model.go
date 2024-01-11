package vulnr

type Item struct {
	Title string
	Value string
}

type Details struct {
	Title string
	Items []Item
}

type Vulnerability struct {
	ID          string
	Title       string
	Category    string
	Severity    string
	Description string
	References  []string
	Details     []Details
}

package api

import "context"

type Client interface {
	GetPolicies(ctx context.Context) ([]PolicyListItem, error)
	GetPolicy(ctx context.Context, name string) (*Policy, error)
	CreateException(ctx context.Context, request ExceptionRequest) (*ExceptionResponse, error)
}

type PolicyListItem struct {
	Category    string `json:"category"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity,omitempty"`
}

type Engine struct {
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Subjects []string `json:"subjects,omitempty"`
}

type SourceCode struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type DetailsItem struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

type Details struct {
	Title string        `json:"title"`
	Items []DetailsItem `json:"items"`
}

type Reference struct {
	URL string `json:"url"`
}

type Policy struct {
	Category    string        `json:"category"`
	Namespace   string        `json:"namespace,omitempty"`
	Name        string        `json:"name"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    string        `json:"severity,omitempty"`
	Engine      *Engine       `json:"engine,omitempty"`
	SourceCode  *SourceCode   `json:"code,omitempty"`
	References  []Reference   `json:"references,omitempty"`
	Details     []DetailsItem `json:"details,omitempty"`
	Additional  []Details     `json:"additional,omitempty"`
}

type Resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
}

type ExceptionPolicy struct {
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

type ExceptionRequest struct {
	Resource Resource        `json:"resource"`
	Policy   ExceptionPolicy `json:"policy"`
}

type ExceptionResponse struct {
	Resource string `json:"resource,omitempty"`
}

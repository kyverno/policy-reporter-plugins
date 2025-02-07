package vulnr

import (
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Database struct {
	config db.Config
	close  func() error
}

func (d *Database) Get(id string) (*types.Vulnerability, error) {
	v, err := d.config.GetVulnerability(id)
	if err != nil {
		return nil, err
	}

	if v.Title == "" && v.Severity == "UNKNOWN" {
		return nil, fmt.Errorf("vulnr %s not found", id)
	}

	return &v, err
}

func NewDatabase(path string) (*Database, error) {
	err := db.Init(path)
	if err != nil {
		return nil, err
	}

	return &Database{
		config: db.Config{},
		close:  db.Close,
	}, nil
}

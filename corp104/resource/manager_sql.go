package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/ory/sqlcon"
	"github.com/pkg/errors"
	"github.com/rubenv/sql-migrate"
	"strings"
)

var sharedMigrations = []*migrate.Migration{
	{
		Id: "1",
		Up: []string{`CREATE TABLE IF NOT EXISTS hydra_resource (
	urn      	varchar(255) NOT NULL PRIMARY KEY,
	content  	json NOT NULL
)`},
		Down: []string{
			"DROP TABLE hydra_resource",
		},
	},
}

var Migrations = map[string]*migrate.MemoryMigrationSource{
	"mysql": {Migrations: []*migrate.Migration{
		sharedMigrations[0],
	}},
	"postgres": {Migrations: []*migrate.Migration{
		sharedMigrations[0],
	}},
}

type SQLManager struct {
	DB *sqlx.DB
}

type sqlData struct {
	Urn     string `db:"urn"`
	Content string `db:"content"`
}

var sqlParams = []string{
	"urn",
	"content",
}

func sqlDataFromResource(d *Resource) (*sqlData, error) {
	content, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return &sqlData{
		Urn:     d.GetUrn(),
		Content: string(content),
	}, nil
}

func (d *sqlData) ToResource() (*Resource, error) {
	var r Resource
	err := json.Unmarshal([]byte(d.Content), &r)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (m *SQLManager) CreateSchemas() (int, error) {
	database := m.DB.DriverName()
	switch database {
	case "pgx", "pq":
		database = "postgres"
	}

	migrate.SetTable("hydra_resource_migration")
	n, err := migrate.Exec(m.DB.DB, m.DB.DriverName(), Migrations[database], migrate.Up)
	if err != nil {
		return 0, errors.Wrapf(err, "Could not migrate sql schema, applied %d Migrations", n)
	}
	return n, nil
}

func (m *SQLManager) GetResource(ctx context.Context, urn string) (*Resource, error) {
	var d sqlData
	if err := m.DB.Get(&d, m.DB.Rebind("SELECT * FROM hydra_resource WHERE urn=?"), urn); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	return d.ToResource()
}

func (m *SQLManager) UpdateResource(ctx context.Context, r *Resource) error {
	_, err := m.GetResource(context.Background(), r.GetUrn())
	if err != nil {
		return errors.WithStack(err)
	}

	s, err := sqlDataFromResource(r)
	if err != nil {
		return errors.WithStack(err)
	}

	var query []string
	for _, param := range sqlParams {
		query = append(query, fmt.Sprintf("%s=:%s", param, param))
	}

	if _, err := m.DB.NamedExec(fmt.Sprintf(`UPDATE hydra_resource SET %s WHERE urn=:urn`, strings.Join(query, ", ")), s); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) CreateResource(ctx context.Context, r *Resource) error {
	data, err := sqlDataFromResource(r)
	if err != nil {
		return errors.WithStack(err)
	}

	if _, err := m.DB.NamedExec(fmt.Sprintf(
		"INSERT INTO hydra_resource (%s) VALUES (%s)",
		strings.Join(sqlParams, ", "),
		":"+strings.Join(sqlParams, ", :"),
	), data); err != nil {
		return sqlcon.HandleError(err)
	}

	return nil
}

func (m *SQLManager) DeleteResource(ctx context.Context, urn string) error {
	if _, err := m.DB.Exec(m.DB.Rebind(`DELETE FROM hydra_resource WHERE urn=?`), urn); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) GetResources(ctx context.Context, limit, offset int) (map[string]Resource, error) {
	d := make([]sqlData, 0)
	resources := make(map[string]Resource)

	if err := m.DB.Select(&d, m.DB.Rebind("SELECT * FROM hydra_resource ORDER BY urn LIMIT ? OFFSET ?"), limit, offset); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	for _, k := range d {
		c, err := k.ToResource()
		if err != nil {
			return nil, errors.WithStack(err)
		}

		resources[k.Urn] = *c
	}
	return resources, nil
}

func (m *SQLManager) GetAllScopeNames() ([]string, error) {
	d := make([]sqlData, 0)
	resources := make(map[string]Resource)

	if err := m.DB.Select(&d, "SELECT * FROM hydra_resource ORDER BY urn"); err != nil {
		return nil, sqlcon.HandleError(err)
	}
	var scopes []string
	for _, resource := range resources {
		for _, scope := range resource.Scopes {
			scopes = append(scopes, scope.Name)
		}
	}
	return scopes, nil
}

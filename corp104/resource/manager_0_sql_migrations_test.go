package resource_test

import (
	"fmt"
	"log"
	"sync"
	"testing"

	"context"

	"github.com/jmoiron/sqlx"
	"github.com/ory/hydra/corp104/resource"
	"github.com/ory/sqlcon/dockertest"
	"github.com/rubenv/sql-migrate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var createResourceMigrations = []*migrate.Migration{
	{
		Id: "urn:104:v3:resource:resume:v1.0",
		Up: []string{
			`INSERT INTO hydra_resource (urn, content) VALUES ('urn:104:v3:resource:resume:v1.0', '{"urn":"urn:104:v3:resource:resume:v1.0","uri":"https://v3ms.104.com.tw/resume","name":"resume","scope_auth_type":"company","grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer"],"scopes":[{"name":"resume:v1.0:semi-read","scope_auth_type":"","description":"讀半顯履歷資料"},{"name":"resume:v1.0:read","scope_auth_type":"","description":"讀履歷資料"}],"paths":[{"name":"/{resume_id}","methods":[{"name":"GET","description":"取得 resume 資料","scopes":["resume:v1.0:semi-read","resume:v1.0:read"]}]},{"name":"/","methods":[{"name":"GET","description":"取得 resume 列表","scopes":["resume:v1.0:semi-read","resume:v1.0:read"]}]}],"version":"1.0","contacts":["some.one@104.com.tw"],"description":"履歷資料API"}')`,
		},
		Down: []string{
			`DELETE FROM hydra_resource WHERE urn='1-data'`,
		},
	},
}

var migrations = map[string]*migrate.MemoryMigrationSource{
	"mysql": {
		Migrations: []*migrate.Migration{
			{Id: "0-data", Up: []string{"DROP TABLE IF EXISTS hydra_resource"}},
			resource.Migrations["mysql"].Migrations[0],
			createResourceMigrations[0],
		},
	},
	"postgres": {
		Migrations: []*migrate.Migration{
			{Id: "0-data", Up: []string{"DROP TABLE IF EXISTS hydra_resource"}},
			resource.Migrations["postgres"].Migrations[0],
			createResourceMigrations[0],
		},
	},
}

func TestMigrations(t *testing.T) {
	var m sync.Mutex
	var dbs = map[string]*sqlx.DB{}
	if testing.Short() {
		return
	}

	dockertest.Parallel([]func(){
		func() {
			db, err := dockertest.ConnectToTestPostgreSQL()
			if err != nil {
				log.Fatalf("Could not connect to database: %v", err)
			}
			m.Lock()
			dbs["postgres"] = db
			m.Unlock()
		},
		func() {
			db, err := dockertest.ConnectToTestMySQL()
			if err != nil {
				log.Fatalf("Could not connect to database: %v", err)
			}
			m.Lock()
			dbs["mysql"] = db
			m.Unlock()
		},
	})

	for k, db := range dbs {
		t.Run(fmt.Sprintf("database=%s", k), func(t *testing.T) {
			migrate.SetTable("hydra_resource_migration_integration")
			for step := range migrations[k].Migrations {
				t.Run(fmt.Sprintf("step=%d", step), func(t *testing.T) {
					n, err := migrate.ExecMax(db.DB, db.DriverName(), migrations[k], migrate.Up, 1)
					require.NoError(t, err)
					require.Equal(t, n, 1)
				})
			}

			for _, key := range []string{"urn:104:v3:resource:resume:v1.0"} {
				t.Run("resource="+key, func(t *testing.T) {
					s := &resource.SQLManager{DB: db}
					c, err := s.GetResource(context.TODO(), key)
					require.NoError(t, err)
					assert.EqualValues(t, c.Urn, key)
				})
			}

			for step := range migrations[k].Migrations {
				t.Run(fmt.Sprintf("step=%d", step), func(t *testing.T) {
					n, err := migrate.ExecMax(db.DB, db.DriverName(), migrations[k], migrate.Down, 1)
					require.NoError(t, err)
					require.Equal(t, n, 1)
				})
			}
		})
	}
}

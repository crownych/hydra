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
		Id: "urn:104:v3:resource:rest:jobs",
		Up: []string{
			`INSERT INTO hydra_resource (urn, content) VALUES ('urn:104:v3:resource:rest:jobs', '{"urn":"urn:104:v3:resource:rest:jobs","uri":"https://v3ms.104.com.tw/jobs","name":"jobs","type":"rest","auth_service":"https://v3auth.104.com.tw","default_scope":"rest:jobs","default_scope_auth_type":"company","grant_types":["urn:ietf:params:oauth:grant-type:jwt-bearer","client_credentials"],"scopes":[{"name":"rest:jobs:read","scope_auth_type":"","description":"關於rest:jobs:read"},{"name":"rest:jobs:write","scope_auth_type":"","description":"關於rest:jobs:write"}],"paths":[{"name":"/","methods":[{"name":"GET","description":"取得 job 列表","scopes":["rest:jobs:read","rest:jobs:write"]}]},{"name":"/","methods":[{"name":"POST","description":"取得 job 列表","scopes":["rest:jobs:write"]}]},{"name":"/{jobNo}","methods":[{"name":"GET","description":"取得 job 資料","scopes":["rest:jobs:read","rest:job:write"]}]},{"name":"/{jobNo}","methods":[{"name":"DELETE","description":"刪除 job 資料","scopes":["rest:jobs:write"]}]},{"name":"/{jobNo}","methods":[{"name":"PATCH","description":"修改 job 資料","scopes":["rest:jobs:write"]}]}],"contacts":["someone@104.com.tw"],"description":"公司資料"}')`,
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

			for _, key := range []string{"urn:104:v3:resource:rest:jobs"} {
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

/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 */

package jwk

import (
	"encoding/json"
	"time"

	"context"

	"github.com/jmoiron/sqlx"
	"github.com/ory/hydra/pkg"
	"github.com/ory/sqlcon"
	"github.com/pkg/errors"
	"github.com/rubenv/sql-migrate"
	"gopkg.in/square/go-jose.v2"
)

type SQLManager struct {
	DB     *sqlx.DB
	Cipher *AEAD
}

func NewSQLManager(db *sqlx.DB, key []byte) *SQLManager {
	return &SQLManager{DB: db, Cipher: &AEAD{Key: key}}
}

var Migrations = &migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		{
			Id: "1",
			Up: []string{
				`CREATE TABLE IF NOT EXISTS hydra_jwk (
	sid     varchar(255) NOT NULL,
	kid 	varchar(255) NOT NULL,
	version int NOT NULL DEFAULT 0,
	keydata text NOT NULL,
	PRIMARY KEY (sid, kid)
)`,
			},
			Down: []string{
				"DROP TABLE hydra_jwk",
			},
		},
		{
			Id: "2",
			Up: []string{
				`ALTER TABLE hydra_jwk ADD created_at TIMESTAMP NOT NULL DEFAULT NOW()`,
			},
			Down: []string{
				`ALTER TABLE hydra_jwk DROP COLUMN created_at`,
			},
		},
		// See https://github.com/ory/hydra/issues/921
		{
			Id: "3",
			Up: []string{
				`DELETE FROM hydra_jwk WHERE sid='hydra.openid.id-token'`,
			},
			Down: []string{},
		},
	},
}

type sqlData struct {
	Set       string    `db:"sid"`
	KID       string    `db:"kid"`
	Version   int       `db:"version"`
	CreatedAt time.Time `db:"created_at"`
	Key       string    `db:"keydata"`
}

func (m *SQLManager) sqlDataFromJSONWebKey(set string, key *pkg.JSONWebKey, cipher *AEAD) (*sqlData, error) {
	out, err := json.Marshal(key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if cipher == nil {
		cipher = m.Cipher
	}

	encrypted, err := cipher.Encrypt(out)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	data := &sqlData{
		Set:     set,
		KID:     key.KeyID,
		Version: 0,
		Key:     encrypted,
	}

	return data, nil
}

func (m *SQLManager) sqlDataToJSONWebKey(d sqlData) (*pkg.JSONWebKey, error) {
	key, err := m.Cipher.Decrypt(d.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var c pkg.JSONWebKey
	if err := json.Unmarshal(key, &c); err != nil {
		return nil, errors.WithStack(err)
	}

	return &c, nil
}

func (m *SQLManager) CreateSchemas() (int, error) {
	migrate.SetTable("hydra_jwk_migration")
	n, err := migrate.Exec(m.DB.DB, m.DB.DriverName(), Migrations, migrate.Up)
	if err != nil {
		return 0, errors.Wrapf(err, "Could not migrate sql schema, applied %d Migrations", n)
	}
	return n, nil
}

func (m *SQLManager) AddKey(ctx context.Context, set string, key *pkg.JSONWebKey) error {
	data, err := m.sqlDataFromJSONWebKey(set, key, m.Cipher)
	if err != nil {
		return err
	}

	if _, err = m.DB.NamedExec(`INSERT INTO hydra_jwk (sid, kid, version, keydata) VALUES (:sid, :kid, :version, :keydata)`, data); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) AddKeySet(ctx context.Context, set string, keys *pkg.JSONWebKeySet) error {
	tx, err := m.DB.Beginx()
	if err != nil {
		return errors.WithStack(err)
	}

	if err := m.addKeySet(ctx, tx, m.Cipher, set, keys); err != nil {
		if re := tx.Rollback(); re != nil {
			return errors.Wrap(err, re.Error())
		}
		return sqlcon.HandleError(err)
	}

	if err := tx.Commit(); err != nil {
		if re := tx.Rollback(); re != nil {
			return errors.Wrap(err, re.Error())
		}
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) addKeySet(ctx context.Context, tx *sqlx.Tx, cipher *AEAD, set string, keys *pkg.JSONWebKeySet) error {
	for _, key := range keys.Keys {
		data, err := m.sqlDataFromJSONWebKey(set, &key, cipher)
		if err != nil {
			return err
		}

		if _, err = tx.NamedExec(`INSERT INTO hydra_jwk (sid, kid, version, keydata) VALUES (:sid, :kid, :version, :keydata)`, data); err != nil {
			return sqlcon.HandleError(err)
		}
	}

	return nil
}

func (m *SQLManager) GetKey(ctx context.Context, set, kid string) (*jose.JSONWebKeySet, error) {
	jwks, err := m.GetActualKey(ctx, set, kid)
	if err != nil {
		return nil, err
	}

	return jwks.ToJoseJSONWebKeySet(), nil
}

func (m *SQLManager) GetActualKey(ctx context.Context, set, kid string) (*pkg.JSONWebKeySet, error) {
	var d sqlData
	if err := m.DB.Get(&d, m.DB.Rebind("SELECT * FROM hydra_jwk WHERE sid=? AND kid=? ORDER BY created_at DESC"), set, kid); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	key, err := m.sqlDataToJSONWebKey(d)
	if err != nil {
		return nil, err
	}

	return &pkg.JSONWebKeySet{
		Keys: []pkg.JSONWebKey{*key},
	}, nil
}

func (m *SQLManager) GetKeySet(ctx context.Context, set string) (*jose.JSONWebKeySet, error) {
	jwks, err := m.GetActualKeySet(ctx, set, ActiveJWKFilter)
	if err != nil {
		return nil, err
	}

	return jwks.ToJoseJSONWebKeySet(), nil
}

func (m *SQLManager) GetActualKeySet(ctx context.Context, set string, filter... func(pkg.JSONWebKey) bool) (*pkg.JSONWebKeySet, error) {
	var ds []sqlData
	if err := m.DB.Select(&ds, m.DB.Rebind("SELECT * FROM hydra_jwk WHERE sid=? ORDER BY created_at DESC"), set); err != nil {
		return nil, sqlcon.HandleError(err)
	}

	if len(ds) == 0 {
		return nil, errors.Wrap(pkg.ErrNotFound, "")
	}

	keys := &pkg.JSONWebKeySet{Keys: []pkg.JSONWebKey{}}
	for _, d := range ds {
		key, err := m.sqlDataToJSONWebKey(d)
		if err != nil {
			return nil, err
		}

		if len(filter) > 0 {
			if filter[0](*key) {
				keys.Keys = append(keys.Keys, *key)
			}
		} else {
			keys.Keys = append(keys.Keys, *key)
		}
	}

	if len(keys.Keys) == 0 {
		return nil, errors.WithStack(pkg.ErrNotFound)
	}

	return keys, nil
}

func (m *SQLManager) DeleteKey(ctx context.Context, set, kid string) error {
	if _, err := m.DB.Exec(m.DB.Rebind(`DELETE FROM hydra_jwk WHERE sid=? AND kid=?`), set, kid); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) DeleteKeySet(ctx context.Context, set string) error {
	tx, err := m.DB.Beginx()
	if err != nil {
		return errors.WithStack(err)
	}

	if err := m.deleteKeySet(ctx, tx, set); err != nil {
		if re := tx.Rollback(); re != nil {
			return errors.Wrap(err, re.Error())
		}
		return sqlcon.HandleError(err)
	}

	if err := tx.Commit(); err != nil {
		if re := tx.Rollback(); re != nil {
			return errors.Wrap(err, re.Error())
		}
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) deleteKeySet(ctx context.Context, tx *sqlx.Tx, set string) error {
	if _, err := tx.Exec(m.DB.Rebind(`DELETE FROM hydra_jwk WHERE sid=?`), set); err != nil {
		return sqlcon.HandleError(err)
	}
	return nil
}

func (m *SQLManager) RotateKeys(new *AEAD) error {
	sids := make([]string, 0)
	if err := m.DB.Select(&sids, "SELECT sid FROM hydra_jwk GROUP BY sid"); err != nil {
		return sqlcon.HandleError(err)
	}

	sets := make([]pkg.JSONWebKeySet, 0)
	for _, sid := range sids {
		set, err := m.GetActualKeySet(context.TODO(), sid)
		if err != nil {
			return errors.WithStack(err)
		}
		sets = append(sets, *set)
	}

	tx, err := m.DB.Beginx()
	if err != nil {
		return errors.WithStack(err)
	}

	for k, set := range sets {
		if err := m.deleteKeySet(context.TODO(), tx, sids[k]); err != nil {
			if re := tx.Rollback(); re != nil {
				return errors.Wrap(err, re.Error())
			}
			return sqlcon.HandleError(err)
		}

		if err := m.addKeySet(context.TODO(), tx, new, sids[k], &set); err != nil {
			if re := tx.Rollback(); re != nil {
				return errors.Wrap(err, re.Error())
			}
			return sqlcon.HandleError(err)
		}
	}

	if err := tx.Commit(); err != nil {
		if re := tx.Rollback(); re != nil {
			return errors.Wrap(err, re.Error())
		}
		return sqlcon.HandleError(err)
	}
	return nil
}

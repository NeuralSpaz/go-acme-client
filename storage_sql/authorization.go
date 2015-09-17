package storage_sql

import (
	"database/sql"
	"encoding/json"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
	"time"
)

// --------------------------------------------------------------------
// implementations for i.StorageAuthorization
// --------------------------------------------------------------------

func (sauth *sqlStorageAuthorization) Storage() i.Storage {
	return sauth.storage
}

func (sauth *sqlStorageAuthorization) StorageDirectory() i.StorageDirectory {
	return sauth.registration.directory
}

func (sauth *sqlStorageAuthorization) Directory() *types.Directory {
	return sauth.StorageDirectory().Directory()
}

func (sauth *sqlStorageAuthorization) StorageRegistration() i.StorageRegistration {
	return sauth.registration
}

func (sauth *sqlStorageAuthorization) Authorization() *types.Authorization {
	return &sauth.authorization
}

func (sauth *sqlStorageAuthorization) SetAuthorization(authorization types.Authorization) error {
	if err := sauth.storage.saveAuthorization(sauth.id, sauth.registration.id, authorization); nil != err {
		return err
	}
	sauth.authorization = authorization
	return nil
}

func (sauth *sqlStorageAuthorization) Delete() error {
	if _, err := sauth.storage.db.Exec(`DELETE FROM authorization WHERE id = $1`, sauth.id); nil != err {
		return err
	}
	sauth.id = -1
	sauth.authorization = types.Authorization{}
	return nil
}

// --------------------------------------------------------------------
// end [implementations for i.StorageAuthorization]
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// implementations for i.StorageRegistration
// --------------------------------------------------------------------

func (sreg *sqlStorageRegistration) NewAuthorization(auth types.Authorization) (i.StorageAuthorization, error) {
	export, err := auth.Export(sreg.storage.lastPassword())
	if nil != err {
		return nil, err
	}

	_, err = sreg.storage.db.Exec(
		`INSERT INTO authorization (registration_id, dnsName, location, status, expires, jsonPem) VALUES
			($1, $2, $3, $4, $5, $6)`,
		sreg.id, string(auth.Resource.DNSIdentifier), auth.Location,
		string(auth.Resource.Status), auth.Resource.Expires, export.JsonPem)
	if nil != err {
		return nil, err
	}

	return sreg.LoadAuthorization(auth.Location)
}

func (sreg *sqlStorageRegistration) AuthorizationInfos() (i.AuthorizationInfos, error) {
	rows, err := sreg.storage.db.Query(
		`SELECT dnsName, location, status, strftime('%Y-%m-%dT%H:%M:%fZ', expires) FROM authorization WHERE registration_id = $1 ORDER BY id DESC`,
		sreg.id)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return authInfoListFromRows(rows)
}

func (sreg *sqlStorageRegistration) AuthorizationInfosWithStatus(status types.AuthorizationStatus) (i.AuthorizationInfos, error) {
	rows, err := sreg.storage.db.Query(
		`SELECT dnsName, location, status, strftime('%Y-%m-%dT%H:%M:%fZ', expires) FROM authorization WHERE registration_id = $1 AND status = $2 ORDER BY id DESC`,
		sreg.id, string(status))
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return authInfoListFromRows(rows)
}

func (sreg *sqlStorageRegistration) Authorizations() ([]i.StorageAuthorization, error) {
	if rows, err := sreg.storage.db.Query(
		"SELECT id, registration_id, jsonPem FROM authorization WHERE registration_id = $1", sreg.id); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		result := []i.StorageAuthorization{}
		for {
			if sauth, err := sreg.storage.loadAuthorizationFromSql(rows, sreg); nil != err {
				return nil, err
			} else if nil == sauth {
				return result, nil
			} else {
				result = append(result, sauth)
			}
		}
	}
}

func (sreg *sqlStorageRegistration) LoadAuthorization(locationOrDnsIdentifier string) (i.StorageAuthorization, error) {
	if auth, err := sreg.LoadAuthorizationByURL(locationOrDnsIdentifier); nil != err {
		return nil, err
	} else if auth != nil {
		return auth, nil
	} else {
		return sreg.LoadAuthorizationByDNS(locationOrDnsIdentifier)
	}
}

func (sreg *sqlStorageRegistration) LoadAuthorizationByURL(authorizationURL string) (i.StorageAuthorization, error) {
	if sauth, err := sreg.storage.loadAuthorizationByLocation(authorizationURL, sreg); nil != err || nil == sauth {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return sauth, nil
	}
}

func (sreg *sqlStorageRegistration) LoadAuthorizationByDNS(dnsIdentifier string) (i.StorageAuthorization, error) {
	if sauth, err := sreg.loadAuthorizationByDnsIdentifier(dnsIdentifier); nil != err || nil == sauth {
		// make sure to create a nil interface from the nil pointer!
		return nil, err
	} else {
		return sauth, nil
	}
}

// --------------------------------------------------------------------
// end [implementations for i.StorageRegistration]
// --------------------------------------------------------------------

type sqlStorageAuthorization struct {
	storage       *sqlStorage
	registration  *sqlStorageRegistration
	id            int64
	authorization types.Authorization
}

func (storage *sqlStorage) checkAuthorizationTable() error {
	_, err := storage.db.Exec(
		`CREATE TABLE IF NOT EXISTS authorization (
			id INTEGER PRIMARY KEY,
			registration_id INT NOT NULL,
			jsonPem BLOB NOT NULL,
			dnsName TEXT NOT NULL,
			location TEXT NOT NULL,
			status TEXT NOT NULL,
			expires TEXT,
			FOREIGN KEY(registration_id) REFERENCES registration(id),
			UNIQUE (location)
		)`)
	return err
}

func timeFromSql(sqlTime sql.NullString) (*time.Time, error) {
	if sqlTime.Valid {
		timeStamp := &time.Time{}
		if timeStampJson, err := json.Marshal(sqlTime.String); nil != err {
			return nil, err
		} else if err := json.Unmarshal(timeStampJson, timeStamp); nil != err {
			return nil, err
		}
		return timeStamp, nil
	} else {
		return nil, nil
	}
}

func authInfoListFromRows(rows *sql.Rows) (i.AuthorizationInfos, error) {
	regs := make(map[string][]i.AuthorizationInfo)
	for rows.Next() {
		var dnsName string
		var location string
		var status string
		var expiresString sql.NullString
		if err := rows.Scan(&dnsName, &location, &status, &expiresString); nil != err {
			return nil, err
		}
		expires, err := timeFromSql(expiresString)
		if nil != err {
			return nil, err
		}
		regs[dnsName] = append(regs[dnsName], i.AuthorizationInfo{
			DNSIdentifier: dnsName,
			Location:      location,
			Status:        types.AuthorizationStatus(status),
			Expires:       expires,
		})
	}
	return i.AuthorizationInfos(regs), nil
}

func (storage *sqlStorage) loadAuthorizationFromSql(rows *sql.Rows, sregHint *sqlStorageRegistration) (*sqlStorageAuthorization, error) {
	if !rows.Next() {
		return nil, nil
	}

	var id, registration_id int64
	var jsonPem []byte
	if err := rows.Scan(&id, &registration_id, &jsonPem); nil != err {
		return nil, err
	}

	if nil == sregHint || registration_id != sregHint.id {
		if sreg, err := storage.loadRegistrationById(registration_id, nil); nil != err {
			return nil, err
		} else {
			sregHint = sreg
		}
	}

	auth := &sqlStorageAuthorization{
		storage:      storage,
		registration: sregHint,
		id:           id,
	}

	if err := auth.authorization.Import(
		types.AuthorizationExport{
			JsonPem: jsonPem,
		}, storage.passwordPrompt); nil != err {
		return nil, err
	}

	return auth, nil
}

func (storage *sqlStorage) loadAuthorizationByLocation(location string, sregHint *sqlStorageRegistration) (*sqlStorageAuthorization, error) {
	if rows, err := storage.db.Query(
		"SELECT id, registration_id, jsonPem FROM authorization WHERE location = $1", location); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		return storage.loadAuthorizationFromSql(rows, sregHint)
	}
}

func (sreg *sqlStorageRegistration) loadAuthorizationByDnsIdentifier(dnsIdentifier string) (*sqlStorageAuthorization, error) {
	if rows, err := sreg.storage.db.Query(
		`SELECT
			id, registration_id, jsonPem
		FROM authorization
		WHERE registration_id = $1
			AND dnsName = $2
			AND (status = 'valid' OR status = 'pending' OR status = '' OR status = 'processing')
			AND (expires IS NULL OR expires > CURRENT_TIMESTAMP)
		ORDER BY id DESC LIMIT 1`, sreg.id, dnsIdentifier); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		return sreg.storage.loadAuthorizationFromSql(rows, sreg)
	}
}

func (storage *sqlStorage) saveAuthorization(id int64, registration_id int64, auth types.Authorization) error {
	export, err := auth.Export(storage.lastPassword())
	if nil != err {
		return err
	}

	_, err = storage.db.Exec(
		`UPDATE authorization SET
			registration_id = $1, dnsName = $2, location = $3,
			status = $4, expires = $5, jsonPem = $6
		WHERE id = $7`,
		registration_id,
		string(auth.Resource.DNSIdentifier), auth.Location,
		string(auth.Resource.Status), auth.Resource.Expires, export.JsonPem,
		id)

	return err
}

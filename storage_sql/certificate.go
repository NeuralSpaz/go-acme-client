package storage_sql

import (
	"database/sql"
	i "github.com/stbuehler/go-acme-client/storage_interface"
	"github.com/stbuehler/go-acme-client/types"
)

// --------------------------------------------------------------------
// implementations for i.StorageCertificate
// --------------------------------------------------------------------

func (scert *sqlStorageCertificate) Storage() i.Storage {
	return scert.storage
}

func (scert *sqlStorageCertificate) StorageDirectory() i.StorageDirectory {
	return scert.registration.directory
}

func (scert *sqlStorageCertificate) Directory() *types.Directory {
	return scert.StorageDirectory().Directory()
}

func (scert *sqlStorageCertificate) StorageRegistration() i.StorageRegistration {
	return scert.registration
}

func (scert *sqlStorageCertificate) Certificate() *types.Certificate {
	return &scert.certificate
}

func (scert *sqlStorageCertificate) Delete() error {
	if _, err := scert.storage.db.Exec(`DELETE FROM certificate WHERE id = %1`, scert.id); nil != err {
		return err
	}
	scert.id = -1
	scert.certificate = types.Certificate{}
	return nil
}

// --------------------------------------------------------------------
// end [implementations for i.StorageCertificate]
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// implementations for i.StorageRegistration
// --------------------------------------------------------------------

func (sreg *sqlStorageRegistration) NewCertificate(cert types.Certificate) (i.StorageCertificate, error) {
	export, err := cert.Export(sreg.storage.lastPassword())
	if nil != err {
		return nil, err
	}

	_, err = sreg.storage.db.Exec(
		`INSERT INTO certificate (registration_id, location, linkIssuer, certificatePem, privateKeyPem) VALUES
			($1, $2, $3, $4, $5)`,
		sreg.id, cert.Location, cert.LinkIssuer,
		export.CertificatePem, export.PrivateKeyPem)
	if nil != err {
		return nil, err
	}

	return sreg.LoadCertificate(cert.Location)
}

func (sreg *sqlStorageRegistration) CertificateInfos() ([]i.CertificateInfo, error) {
	rows, err := sreg.storage.db.Query(
		`SELECT location, linkIssuer FROM certificate WHERE registration_id = $1`,
		sreg.id)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return certInfoListFromRows(rows)
}

func (sreg *sqlStorageRegistration) Certificates() ([]i.StorageCertificate, error) {
	if rows, err := sreg.storage.db.Query(
		`SELECT id, registration_id, location, linkIssuer, certificatePem, privateKeyPem
		FROM certificate
		WHERE registration_id = $1`, sreg.id); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		result := []i.StorageCertificate{}
		for {
			if scert, err := sreg.storage.loadCertificateFromSql(rows, sreg); nil != err {
				return nil, err
			} else if nil == scert {
				return result, nil
			} else {
				result = append(result, scert)
			}
		}
	}
}

func (sreg *sqlStorageRegistration) LoadCertificate(location string) (i.StorageCertificate, error) {
	if rows, err := sreg.storage.db.Query(
		`SELECT id, registration_id, location, linkIssuer, certificatePem, privateKeyPem
		FROM certificate
		WHERE registration_id = $1 AND location = $2`, sreg.id, location); nil != err {
		return nil, err
	} else {
		defer rows.Close()
		if cert, err := sreg.storage.loadCertificateFromSql(rows, sreg); nil != err || nil == cert {
			// make sure to create a nil interface from the nil pointer!
			return nil, err
		} else {
			return cert, nil
		}
	}
}

// --------------------------------------------------------------------
// end [implementations for i.StorageRegistration]
// --------------------------------------------------------------------

type sqlStorageCertificate struct {
	storage      *sqlStorage
	registration *sqlStorageRegistration
	id           int64
	certificate  types.Certificate
}

func (storage *sqlStorage) checkCertificateTable() error {
	_, err := storage.db.Exec(
		`CREATE TABLE IF NOT EXISTS certificate (
			id INTEGER PRIMARY KEY,
			registration_id INT NOT NULL,
			location TEXT NOT NULL,
			linkIssuer TEXT NOT NULL,
			certificatePem BLOB NOT NULL,
			privateKeyPem BLOB,
			FOREIGN KEY(registration_id) REFERENCES registration(id),
			UNIQUE (registration_id, location)
		)`)
	return err
}

func certInfoListFromRows(rows *sql.Rows) ([]i.CertificateInfo, error) {
	var certs []i.CertificateInfo
	for rows.Next() {
		var location string
		var linkIssuer string
		if err := rows.Scan(&location, &linkIssuer); nil != err {
			return nil, err
		}
		certs = append(certs, i.CertificateInfo{
			Location:   location,
			LinkIssuer: linkIssuer,
		})
	}
	return certs, nil
}

func (storage *sqlStorage) loadCertificateFromSql(rows *sql.Rows, sregHint *sqlStorageRegistration) (*sqlStorageCertificate, error) {
	if !rows.Next() {
		return nil, nil
	}

	var id, registration_id int64
	var location, linkIssuer string
	var certificatePem []byte
	var privateKeyPem sql.NullString
	if err := rows.Scan(&id, &registration_id, &location, &linkIssuer, &certificatePem, &privateKeyPem); nil != err {
		return nil, err
	}

	var privKeyPem []byte
	if privateKeyPem.Valid {
		privKeyPem = []byte(privateKeyPem.String)
	}

	cert := &sqlStorageCertificate{
		storage:      storage,
		registration: sregHint,
		id:           id,
	}

	if err := cert.certificate.Import(
		types.CertificateExport{
			CertificatePem: certificatePem,
			PrivateKeyPem:  privKeyPem,
			Location:       location,
			LinkIssuer:     linkIssuer,
		}, storage.passwordPrompt); nil != err {
		return nil, err
	}

	return cert, nil
}

func (storage *sqlStorage) saveCertificate(id int64, registration_id int64, cert types.Certificate) error {
	export, err := cert.Export(storage.lastPassword())
	if nil != err {
		return err
	}

	_, err = storage.db.Exec(
		`UPDATE certificate SET
			registration_id = $1, location = $2, linkIssuer = $3, certificatePem = $4, privateKeyPem = $5
		WHERE id = $6`,
		registration_id, cert.Location, cert.LinkIssuer,
		export.CertificatePem, export.PrivateKeyPem, id)

	return err
}

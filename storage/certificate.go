package storage

import (
	"database/sql"
	"encoding/pem"
	"github.com/stbuehler/go-acme-client/types"
	"github.com/stbuehler/go-acme-client/utils"
)

type StorageCertificate struct {
	storage         Storage
	registration_id int64
	id              int64
	Certificate     types.Certificate
}

type CertificateInfo struct {
	Location   string
	LinkIssuer string
}

func (storage Storage) checkCertificateTable() error {
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

func certInfoListFromRows(rows *sql.Rows) ([]CertificateInfo, error) {
	var certs []CertificateInfo
	for rows.Next() {
		var location string
		var linkIssuer string
		if err := rows.Scan(&location, &linkIssuer); nil != err {
			return nil, err
		}
		certs = append(certs, CertificateInfo{
			Location:   location,
			LinkIssuer: linkIssuer,
		})
	}
	return certs, nil
}

func (registration StorageRegistration) CertificateList() ([]CertificateInfo, error) {
	rows, err := registration.storage.db.Query(
		`SELECT location, linkIssuer FROM certificate WHERE registration_id = $1`,
		registration.id)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	return certInfoListFromRows(rows)
}

func (registration StorageRegistration) LoadCertificate(location string) (*StorageCertificate, error) {
	rows, err := registration.storage.db.Query("SELECT id, linkIssuer, certificatePem, privateKeyPem FROM certificate WHERE registration_id = $1 AND location = $2", registration.id, location)
	if nil != err {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}

	var id int64
	var linkIssuer string
	var certificatePem []byte
	var privateKeyPem sql.NullString
	if err := rows.Scan(&id, &linkIssuer, &certificatePem, &privateKeyPem); nil != err {
		return nil, err
	}
	certificateBlock, err := registration.storage.loadPem(certificatePem, pemTypeCertificate)
	if nil != err {
		return nil, err
	}
	var privateKeyBlock *pem.Block
	if privateKeyPem.Valid {
		privateKeyBlock, err = registration.storage.loadPem([]byte(privateKeyPem.String), pemTypeEcPrivateKey, pemTypeRsaPrivateKey)
		if nil != err {
			return nil, err
		}
	}

	return &StorageCertificate{
		storage:         registration.storage,
		registration_id: registration.id,
		id:              id,
		Certificate: types.Certificate{
			Location:       location,
			LinkIssuer:     linkIssuer,
			PemCertificate: certificateBlock,
			PemPrivateKey:  privateKeyBlock,
		},
	}, nil
}

func (scert StorageCertificate) Save() error {
	var privateKeyBlob []byte
	if nil != scert.Certificate.PemPrivateKey {
		privateKeyBlock := *scert.Certificate.PemPrivateKey
		if err := utils.EncryptPemBlock(&privateKeyBlock, scert.storage.lastPassword(), utils.PemDefaultCipher); nil != err {
			return err
		}
		privateKeyBlob = pem.EncodeToMemory(&privateKeyBlock)
	}

	_, err := scert.storage.db.Exec(
		`INSERT OR REPLACE INTO certificate (id, registration_id, location, linkIssuer, certificatePem, privateKeyPem) VALUES
			($1, $2, $3, $4, $5, $6)`,
		scert.id, scert.registration_id, scert.Certificate.Location, scert.Certificate.LinkIssuer,
		pem.EncodeToMemory(scert.Certificate.PemCertificate), privateKeyBlob)

	return err
}

func (registration StorageRegistration) NewCertificate(certificate types.Certificate) (*StorageCertificate, error) {
	var privateKeyBlob []byte
	if nil != certificate.PemPrivateKey {
		privateKeyBlock := *certificate.PemPrivateKey
		if err := utils.EncryptPemBlock(&privateKeyBlock, registration.storage.lastPassword(), utils.PemDefaultCipher); nil != err {
			return nil, err
		}
		privateKeyBlob = pem.EncodeToMemory(&privateKeyBlock)
	}

	_, err := registration.storage.db.Exec(
		`INSERT INTO certificate (registration_id, location, linkIssuer, certificatePem, privateKeyPem) VALUES
			($1, $2, $3, $4, $5)`,
		registration.id, certificate.Location, certificate.LinkIssuer,
		pem.EncodeToMemory(certificate.PemCertificate), privateKeyBlob)
	if nil != err {
		return nil, err
	}

	return registration.LoadCertificate(certificate.Location)
}

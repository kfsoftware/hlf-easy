/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory_test

import (
	"os"
	"testing"

	. "github.com/onsi/gomega"
	"hlf-easy/internal/github.com/hyperledger/fabric-ca/lib/server/db/factory"
	"hlf-easy/internal/github.com/hyperledger/fabric-ca/lib/server/db/mysql"
	"hlf-easy/internal/github.com/hyperledger/fabric-ca/lib/server/db/postgres"
	"hlf-easy/internal/github.com/hyperledger/fabric-ca/lib/server/db/sqlite"
)

func TestNew(t *testing.T) {
	gt := NewGomegaWithT(t)

	db, err := factory.New("sqlite3", "fabric_ca.db", "", nil, nil, nil)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(db).NotTo(BeNil())
	gt.Expect(db).To(Equal(sqlite.NewDB("fabric_ca.db", "", nil)))

	db, err = factory.New("postgres", "fabric_ca_postgres", "", nil, nil, nil)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(db).NotTo(BeNil())
	gt.Expect(db).To(Equal(postgres.NewDB("fabric_ca_postgres", "", nil, nil)))

	db, err = factory.New("mysql", "fabric_ca_mysql", "", nil, nil, nil)
	gt.Expect(err).NotTo(HaveOccurred())
	gt.Expect(db).NotTo(BeNil())
	gt.Expect(db).To(Equal(mysql.NewDB("fabric_ca_mysql", "", nil, nil, nil)))

	_, err = factory.New("fake", "fabric_ca_mysql", "", nil, nil, nil)
	gt.Expect(err).To(HaveOccurred())

	os.Remove("fabric_ca.db")
}

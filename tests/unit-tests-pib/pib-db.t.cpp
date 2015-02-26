/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2014 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "pib/pib-db.hpp"
#include "security/key-chain.hpp"

#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace ndn {
namespace pib {
namespace tests {

class PibDbTestFixture
{
public:
  PibDbTestFixture()
    : db("/tmp")
  {
  }

  ~PibDbTestFixture()
  {
    boost::filesystem::path TMP_DIR("/tmp/pib.db");
    boost::filesystem::remove_all(TMP_DIR);
  }

  PibDb db;
};


BOOST_FIXTURE_TEST_SUITE(TestPibDb, PibDbTestFixture)

BOOST_AUTO_TEST_CASE(UserTest)
{
  KeyChain keyChain("sqlite3", "file");

  Name root("/localhost/pib/user");
  Name rootCertName = keyChain.createIdentity(root);
  shared_ptr<IdentityCertificate> rootCert = keyChain.getCertificate(rootCertName);

  Name testUser("/localhost/pib/user/test");
  Name testUserCertName = keyChain.createIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = keyChain.getCertificate(testUserCertName);

  db.addRootUser(*rootCert);
  BOOST_CHECK(db.hasUser("root"));
  BOOST_CHECK(static_cast<bool>(db.getUserMgmtCertificate("root")));

  BOOST_CHECK_THROW(db.addRootUser(*testUserCert), PibDb::Error);
  BOOST_CHECK_EQUAL(db.hasUser("test"), false);
  BOOST_CHECK_EQUAL(static_cast<bool>(db.getUserMgmtCertificate("test")), false);

  db.addUser(*testUserCert);
  BOOST_CHECK(db.hasUser("test"));
  BOOST_CHECK(static_cast<bool>(db.getUserMgmtCertificate("test")));

  db.deleteUser("test");
  BOOST_CHECK_EQUAL(db.hasUser("test"), false);
  BOOST_CHECK_EQUAL(static_cast<bool>(db.getUserMgmtCertificate("test")), false);

  db.deleteUser("root");
  BOOST_CHECK_EQUAL(db.hasUser("root"), false);
  BOOST_CHECK_EQUAL(static_cast<bool>(db.getUserMgmtCertificate("root")), false);

  keyChain.deleteIdentity(testUser);
  keyChain.deleteIdentity(root);
}

BOOST_AUTO_TEST_CASE(IdentityTest)
{
  KeyChain keyChain("sqlite3", "file");

  std::string userName("test");
  Name testUser("/localhost/pib/user/test");
  Name testUserCertName = keyChain.createIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = keyChain.getCertificate(testUserCertName);
  db.addUser(*testUserCert);

  Name identity("/test/identity");
  db.addIdentity(userName, identity);
  BOOST_CHECK(db.hasIdentity(userName, identity));

  db.deleteIdentity(userName, identity);
  BOOST_CHECK_EQUAL(db.hasIdentity(userName, identity), false);

  db.addIdentity(userName, identity);
  BOOST_CHECK_THROW(db.getDefaultIdentityOfUser(userName), PibDb::Error);
  BOOST_CHECK_THROW(db.getDefaultIdentityOfUser("NonExistingUser"), PibDb::Error);
  db.setDefaultIdentityOfUser(userName, identity);
  BOOST_REQUIRE_NO_THROW(db.getDefaultIdentityOfUser(userName));
  BOOST_CHECK_EQUAL(db.getDefaultIdentityOfUser(userName), identity);

  db.deleteUser(userName);
  keyChain.deleteIdentity(testUser);
}


BOOST_AUTO_TEST_CASE(KeyTest)
{
  KeyChain keyChain("sqlite3", "file");

  std::string userName("test");
  Name testUser("/localhost/pib/user/test");
  Name testUserCertName = keyChain.createIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = keyChain.getCertificate(testUserCertName);
  db.addUser(*testUserCert);

  Name testId("/test/identity");
  db.addIdentity(userName, testId);
  Name testIdCertName = keyChain.createIdentity(testId);
  Name testIdKeyName = keyChain.getDefaultKeyNameForIdentity(testId);
  const name::Component& keyId = testIdKeyName[-1];
  shared_ptr<PublicKey> key = keyChain.getPublicKey(testIdKeyName);

  BOOST_CHECK_EQUAL(static_cast<bool>(db.getKey(userName, testId, keyId)), false);
  db.addKey(userName, testId, keyId, *key);
  BOOST_CHECK_EQUAL(static_cast<bool>(db.getKey(userName, testId, keyId)), true);

  BOOST_CHECK_THROW(db.getDefaultKeyNameOfIdentity(userName, testId), PibDb::Error);
  BOOST_CHECK_THROW(db.getDefaultKeyNameOfIdentity(userName, Name("/nonId")), PibDb::Error);
  BOOST_CHECK_THROW(db.getDefaultKeyNameOfIdentity("NonExistingUser", testId), PibDb::Error);
  db.setDefaultKeyNameOfIdentity(userName, testId, keyId);
  BOOST_REQUIRE_NO_THROW(db.getDefaultKeyNameOfIdentity(userName, testId));
  BOOST_CHECK_EQUAL(db.getDefaultKeyNameOfIdentity(userName, testId), testIdKeyName);

  db.deleteUser(userName);
  keyChain.deleteIdentity(testId);
  keyChain.deleteIdentity(testUser);
}

BOOST_AUTO_TEST_CASE(CertTest)
{
  KeyChain keyChain("sqlite3", "file");

  std::string userName("test");
  Name testUser("/localhost/pib/user/test");
  Name testUserCertName = keyChain.createIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = keyChain.getCertificate(testUserCertName);
  db.addUser(*testUserCert);

  Name testId("/test/identity");
  db.addIdentity(userName, testId);
  Name testIdCertName = keyChain.createIdentity(testId);
  Name testIdKeyName = keyChain.getDefaultKeyNameForIdentity(testId);
  const name::Component& keyId = testIdKeyName[-1];
  shared_ptr<PublicKey> key = keyChain.getPublicKey(testIdKeyName);
  db.addKey(userName, testId, keyId, *key);
  shared_ptr<IdentityCertificate> cert = keyChain.getCertificate(testIdCertName);

  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName), false);
  db.addCertificate(userName, *cert);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName), true);

  BOOST_CHECK_THROW(db.getDefaultCertNameOfKey(userName, testId, keyId), PibDb::Error);
  BOOST_CHECK_THROW(db.getDefaultCertNameOfKey(userName, Name("/nonId"), keyId), PibDb::Error);
  BOOST_CHECK_THROW(db.getDefaultCertNameOfKey("NonExistingUser", testId, keyId), PibDb::Error);
  db.setDefaultCertNameOfKey(userName, testId, keyId, testIdCertName);
  BOOST_REQUIRE_NO_THROW(db.getDefaultCertNameOfKey(userName, testId, keyId));
  BOOST_CHECK_EQUAL(db.getDefaultCertNameOfKey(userName, testId, keyId), testIdCertName);

  db.deleteUser(userName);
  keyChain.deleteIdentity(testId);
  keyChain.deleteIdentity(testUser);
}

BOOST_AUTO_TEST_CASE(DeleteTest)
{
  KeyChain keyChain("sqlite3", "file");

  std::string userName("test");
  Name testUser("/localhost/pib/user/test");
  Name testUserCertName = keyChain.createIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = keyChain.getCertificate(testUserCertName);
  db.addUser(*testUserCert);

  Name testId("/test/identity");
  Name testIdCertName00 = keyChain.createIdentity(testId);
  shared_ptr<IdentityCertificate> cert00 = keyChain.getCertificate(testIdCertName00);
  Name testIdKeyName0 = cert00->getPublicKeyName();
  const name::Component& testIdKeyId0 = testIdKeyName0[-1];

  BOOST_CHECK_EQUAL(db.hasIdentity(userName, testId), false);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId0), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName00), false);
  db.addCertificate(userName, *cert00);
  BOOST_CHECK_EQUAL(db.hasIdentity(userName, testId), true);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId0), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName00), true);

  shared_ptr<IdentityCertificate> cert01 = keyChain.selfSign(testIdKeyName0);
  Name testIdCertName01 = cert01->getName();
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName01), false);
  db.addCertificate(userName, *cert01);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName01), true);

  Name testIdKeyName1 = keyChain.generateRsaKeyPair(testId);
  const name::Component& testIdKeyId1 = testIdKeyName1[-1];
  shared_ptr<IdentityCertificate> cert10 = keyChain.selfSign(testIdKeyName1);
  Name testIdCertName10 = cert10->getName();
  shared_ptr<IdentityCertificate> cert11 = keyChain.selfSign(testIdKeyName1);
  Name testIdCertName11 = cert11->getName();

  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId1), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName10), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), false);
  db.addCertificate(userName, *cert10);
  db.addCertificate(userName, *cert11);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId1), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName10), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), true);

  //delete a cert
  db.deleteCertificate(userName, testIdCertName11);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), false);

  db.addCertificate(userName, *cert11);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), true);

  //delete a key
  db.deleteKey(userName, testId, testIdKeyId1);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId1), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName10), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), false);

  db.addCertificate(userName, *cert10);
  db.addCertificate(userName, *cert11);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId1), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName10), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), true);

  //delete an identity
  db.deleteIdentity(userName, testId);
  BOOST_CHECK_EQUAL(db.hasIdentity(userName, testId), false);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId0), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName00), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName01), false);
  BOOST_CHECK_EQUAL(db.hasKey(userName, testId, testIdKeyId1), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName10), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(userName, testIdCertName11), false);

  db.deleteUser(userName);
  keyChain.deleteIdentity(testId);
  keyChain.deleteIdentity(testUser);
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace ndn

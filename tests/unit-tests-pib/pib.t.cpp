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

#include "pib/pib.hpp"
#include "identity-management-time-fixture.hpp"
#include "security/sec-tpm-file.hpp"
#include "security/pib/pib-encoding.hpp"
#include "util/io.hpp"
#include "util/dummy-client-face.hpp"

#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace ndn {
namespace pib {
namespace tests {

class PibTestFixture : public ndn::security::IdentityManagementTimeFixture
{
public:
  PibTestFixture()
    : tmpPath(boost::filesystem::path(TEST_CONFIG_PATH) / "PibTest")
    , face(util::makeDummyClientFace(io, {true, true}))
  {
  }

  ~PibTestFixture()
  {
    boost::filesystem::remove_all(tmpPath);
  }

  template<class Param>
  shared_ptr<Interest>
  generateUnsignedInterest(Param& param, const std::string& user)
  {
    Name command("/localhost/pib");
    command.append(user).append(Param::VERB).append(param.wireEncode());
    shared_ptr<Interest> interest = make_shared<Interest>(command);

    return interest;
  }

  template<class Param>
  shared_ptr<Interest>
  generateSignedInterest(Param& param, const std::string& user, const Name& certName)
  {
    shared_ptr<Interest> interest = generateUnsignedInterest(param, user);
    m_keyChain.sign(*interest, certName);

    return interest;
  }

  std::string owner;
  boost::filesystem::path tmpPath;
  shared_ptr<util::DummyClientFace> face;
};

BOOST_FIXTURE_TEST_SUITE(TestPib, PibTestFixture)

BOOST_AUTO_TEST_CASE(InitCertTest1)
{
  // Create a PIB with full parameters
  owner = "testUser";

  Pib pib(*face,
          tmpPath.string(),
          m_keyChain.getTpm().getTpmLocator(),
          owner);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_CHECK_EQUAL(pib.getOwner(), owner);
  BOOST_CHECK_EQUAL(pib.getDb().getOwnerName(), owner);

  auto mgmtCert = pib.getMgmtCert();
  BOOST_CHECK_EQUAL(mgmtCert.getName().getPrefix(-3),
                    Name("/localhost/pib/testUser/mgmt/KEY"));
  BOOST_CHECK_EQUAL(mgmtCert.getName().get(5).toUri().substr(0, 4), "dsk-");

  auto mgmtCert2 = pib.getDb().getMgmtCertificate();
  BOOST_REQUIRE(mgmtCert2 != nullptr);
  BOOST_CHECK(mgmtCert.wireEncode() == mgmtCert2->wireEncode());

  BOOST_CHECK_EQUAL(pib.getDb().getTpmLocator(), m_keyChain.getTpm().getTpmLocator());

  GetParam param01;
  shared_ptr<Interest> interest01 = generateUnsignedInterest(param01, owner);

  face->receive(*interest01);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibUser result01;
  BOOST_REQUIRE_NO_THROW(result01.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK(result01.getMgmtCert().wireEncode() == mgmtCert.wireEncode());
  BOOST_CHECK_EQUAL(result01.getTpmLocator(), m_keyChain.getTpm().getTpmLocator());
}

BOOST_AUTO_TEST_CASE(InitCertTest2)
{
  // Create a PIB from a database (assume that the database is configured)
  std::string dbDir = tmpPath.string();
  std::string tpmLocator = m_keyChain.getTpm().getTpmLocator();
  owner = "testUser";

  Name testUser("/localhost/pib/testUser/mgmt");
  addIdentity(testUser);
  Name testUserCertName = m_keyChain.getDefaultCertificateNameForIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = m_keyChain.getCertificate(testUserCertName);

  PibDb db(tmpPath.string());
  BOOST_CHECK_NO_THROW(Pib(*face, dbDir, tpmLocator, owner));

  db.updateMgmtCertificate(*testUserCert);
  BOOST_CHECK_NO_THROW(Pib(*face, dbDir, tpmLocator, owner));
  BOOST_CHECK_THROW(Pib(*face, dbDir, tpmLocator, "wrongUser"), Pib::Error);

  db.setTpmLocator(m_keyChain.getTpm().getTpmLocator());
  BOOST_CHECK_NO_THROW(Pib(*face, dbDir, tpmLocator, owner));
  BOOST_CHECK_THROW(Pib(*face, dbDir, "tpm-file:wrong", owner), Pib::Error);

  advanceClocks(time::milliseconds(10));
  m_keyChain.deleteIdentity(testUser);
  BOOST_CHECK_NO_THROW(Pib(*face, dbDir, tpmLocator, owner));
}

BOOST_AUTO_TEST_CASE(InitCertTest3)
{
  std::string dbDir = tmpPath.string();
  std::string tpmLocator = m_keyChain.getTpm().getTpmLocator();
  owner = "testUser";

  Name testUser("/localhost/pib/testUser/mgmt");
  addIdentity(testUser);
  Name testUserCertName = m_keyChain.getDefaultCertificateNameForIdentity(testUser);
  shared_ptr<IdentityCertificate> testUserCert = m_keyChain.getCertificate(testUserCertName);

  Pib pib1(*face, dbDir, tpmLocator, owner);
  BOOST_CHECK_EQUAL(pib1.getMgmtCert().getName().getPrefix(-3),
                    Name("/localhost/pib/testUser/mgmt/KEY"));

  PibDb db(tmpPath.string());
  db.updateMgmtCertificate(*testUserCert);
  Pib pib2(*face, dbDir, tpmLocator, owner);
  BOOST_CHECK_EQUAL(pib2.getMgmtCert().getName(), testUserCertName);

  advanceClocks(time::milliseconds(10));
  m_keyChain.deleteIdentity(testUser);
  Pib pib3(*face, dbDir, tpmLocator, owner);
  BOOST_CHECK(pib3.getMgmtCert().getName() != testUserCertName);
  BOOST_CHECK_EQUAL(pib3.getMgmtCert().getName().getPrefix(-3),
                    Name("/localhost/pib/testUser/mgmt/KEY"));
}

BOOST_AUTO_TEST_CASE(ReadCommandTest)
{
  owner = "alice";

  Pib pib(*face,
          tmpPath.string(),
          m_keyChain.getTpm().getTpmLocator(),
          owner);
  advanceClocks(time::milliseconds(10), 10);
  util::InMemoryStoragePersistent& cache = pib.getResponseCache();
  auto ownerMgmtCert = pib.getMgmtCert();
  m_keyChain.addCertificate(ownerMgmtCert);

  PibDb db(tmpPath.string());

  Name testId("/test/identity");
  Name testIdCertName00 = m_keyChain.createIdentity(testId);
  shared_ptr<IdentityCertificate> cert00 = m_keyChain.getCertificate(testIdCertName00);
  Name testIdKeyName0 = cert00->getPublicKeyName();
  advanceClocks(time::milliseconds(100));
  shared_ptr<IdentityCertificate> cert01 = m_keyChain.selfSign(testIdKeyName0);
  Name testIdCertName01 = cert01->getName();

  advanceClocks(time::milliseconds(100));
  Name testIdKeyName1 = m_keyChain.generateRsaKeyPair(testId);
  shared_ptr<IdentityCertificate> cert10 = m_keyChain.selfSign(testIdKeyName1);
  Name testIdCertName10 = cert10->getName();
  advanceClocks(time::milliseconds(100));
  shared_ptr<IdentityCertificate> cert11 = m_keyChain.selfSign(testIdKeyName1);
  Name testIdCertName11 = cert11->getName();

  BOOST_CHECK_EQUAL(db.hasIdentity(testId), false);
  BOOST_CHECK_EQUAL(db.hasKey(testIdKeyName0), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName00), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName01), false);
  BOOST_CHECK_EQUAL(db.hasKey(testIdKeyName1), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName10), false);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName11), false);

  db.addCertificate(*cert00);
  db.addCertificate(*cert01);
  db.addCertificate(*cert10);
  db.addCertificate(*cert11);
  db.setDefaultIdentity(testId);
  db.setDefaultKeyNameOfIdentity(testIdKeyName0);
  db.setDefaultCertNameOfKey(testIdCertName00);

  BOOST_CHECK_EQUAL(db.hasIdentity(testId), true);
  BOOST_CHECK_EQUAL(db.hasKey(testIdKeyName0), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName00), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName01), true);
  BOOST_CHECK_EQUAL(db.hasKey(testIdKeyName1), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName10), true);
  BOOST_CHECK_EQUAL(db.hasCertificate(testIdCertName11), true);

  // Get Param
  GetParam param01;
  shared_ptr<Interest> interest01 = generateUnsignedInterest(param01, owner);

  face->sentDatas.clear();
  face->receive(*interest01);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest01->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibUser result01;
  BOOST_REQUIRE_NO_THROW(result01.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK(result01.getMgmtCert().wireEncode() == ownerMgmtCert.wireEncode());


  GetParam param02;
  shared_ptr<Interest> interest02 = generateUnsignedInterest(param02, "non-existing");

  face->sentDatas.clear();
  face->receive(*interest02);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_CHECK(cache.find(interest02->getName()) == nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 0);


  GetParam param03(TYPE_ID, testId);
  shared_ptr<Interest> interest03 = generateUnsignedInterest(param03, owner);

  face->sentDatas.clear();
  face->receive(*interest03);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest03->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibIdentity result03;
  BOOST_REQUIRE_NO_THROW(result03.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result03.getIdentity(), testId);


  Name wrongId("/wrong/id");
  GetParam param04(TYPE_ID, wrongId);
  shared_ptr<Interest> interest04 = generateUnsignedInterest(param04, owner);

  face->sentDatas.clear();
  face->receive(*interest04);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest04->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibError result04;
  BOOST_REQUIRE_NO_THROW(result04.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result04.getErrorCode(), ERR_NON_EXISTING_ID);


  GetParam param05(TYPE_KEY, testIdKeyName1);
  shared_ptr<Interest> interest05 = generateUnsignedInterest(param05, owner);

  face->sentDatas.clear();
  face->receive(*interest05);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest05->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibPublicKey result05;
  BOOST_REQUIRE_NO_THROW(result05.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result05.getKeyName(), testIdKeyName1);


  Name wrongKeyName1("/wrong/key/name1");
  GetParam param06(TYPE_KEY, wrongKeyName1);
  shared_ptr<Interest> interest06 = generateUnsignedInterest(param06, owner);

  face->sentDatas.clear();
  face->receive(*interest06);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest06->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibError result06;
  BOOST_REQUIRE_NO_THROW(result06.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result06.getErrorCode(), ERR_NON_EXISTING_KEY);


  GetParam param07(TYPE_CERT, testIdCertName00);
  shared_ptr<Interest> interest07 = generateUnsignedInterest(param07, owner);

  face->sentDatas.clear();
  face->receive(*interest07);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest07->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibCertificate result07;
  BOOST_REQUIRE_NO_THROW(result07.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result07.getCertificate().getName(), testIdCertName00);


  Name wrongCertName1("/wrong/cert/name1");
  GetParam param08(TYPE_CERT, wrongCertName1);
  shared_ptr<Interest> interest08 = generateUnsignedInterest(param08, owner);

  face->sentDatas.clear();
  face->receive(*interest08);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest08->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibError result08;
  BOOST_REQUIRE_NO_THROW(result08.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result08.getErrorCode(), ERR_NON_EXISTING_CERT);


  Name wrongKeyName2;
  GetParam param09(TYPE_KEY, wrongKeyName2);
  shared_ptr<Interest> interest09 = generateUnsignedInterest(param09, owner);

  face->sentDatas.clear();
  face->receive(*interest09);
  advanceClocks(time::milliseconds(10), 10);

  BOOST_REQUIRE(cache.find(interest09->getName()) != nullptr);
  BOOST_REQUIRE_EQUAL(face->sentDatas.size(), 1);
  PibError result09;
  BOOST_REQUIRE_NO_THROW(result09.wireDecode(face->sentDatas[0].getContent().blockFromValue()));
  BOOST_CHECK_EQUAL(result09.getErrorCode(), ERR_WRONG_PARAM);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace ndn

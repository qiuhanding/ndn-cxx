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

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace ndn

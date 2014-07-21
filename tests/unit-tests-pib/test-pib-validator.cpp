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

#include "pib/pib-validator.hpp"
#include "security/pib/update-param.hpp"
#include "security/pib/delete-param.hpp"
#include "security/key-chain.hpp"

#include "boost-test.hpp"
#include "identity-management-fixture.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace pib {
namespace test {

BOOST_FIXTURE_TEST_SUITE(PibTestPibValidator, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(Basic)
{
  boost::filesystem::remove("/tmp/pib.db");
  PibDb db("/tmp");
  PibValidator validator(db);
  db.onUserChanged += bind(&PibValidator::handleUserChange, &validator, _1);
  db.onKeyDeleted += bind(&PibValidator::handleKeyDeletion, &validator, _1, _2, _3);

  Name root("/localhost/pib/user");
  BOOST_REQUIRE(addIdentity(root, RsaKeyParams()));
  shared_ptr<IdentityCertificate> rootCert = getCertificateForIdentity(root);
  db.addRootUser(*rootCert);

  Name testUser("/localhost/pib/user/test");
  BOOST_REQUIRE(addIdentity(testUser, RsaKeyParams()));
  shared_ptr<IdentityCertificate> testUserCert = getCertificateForIdentity(testUser);
  db.addUser(*testUserCert);

  Name testUser2("/localhost/pib/user/test2");
  BOOST_REQUIRE(addIdentity(testUser2, RsaKeyParams()));
  shared_ptr<IdentityCertificate> testUser2Cert = getCertificateForIdentity(testUser2);
  db.addUser(*testUser2Cert);

  Name normalId("/normal/id");
  BOOST_REQUIRE(addIdentity(normalId, RsaKeyParams()));
  shared_ptr<IdentityCertificate> normalIdCert = getCertificateForIdentity(normalId);

  db.addIdentity("test", normalId);
  db.addKey("test", normalId, normalIdCert->getPublicKeyName().get(-1),
            normalIdCert->getPublicKeyInfo());
  db.addCertificate("test", *normalIdCert);

  Name command1("/localhost/pib/test/verb/param");
  shared_ptr<Interest> interest1 = make_shared<Interest>(command1);
  m_keyChain.signByIdentity(*interest1, root);
  // root is trusted for any command, OK.
  validator.validate(*interest1,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(false); });

  Name command2("/localhost/pib/test/verb/param");
  shared_ptr<Interest> interest2 = make_shared<Interest>(command2);
  m_keyChain.signByIdentity(*interest2, testUser);
  // "test" user is trusted for any command about itself, OK.
  validator.validate(*interest2,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(false); });

  Name command3("/localhost/pib/test/verb/param");
  shared_ptr<Interest> interest3 = make_shared<Interest>(command3);
  m_keyChain.signByIdentity(*interest3, testUser2);
  // "test2" user is NOT trusted for any command about other user, MUST fail
  validator.validate(*interest3,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(false); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(true); });

  Name command4("/localhost/pib/test/verb/param");
  shared_ptr<Interest> interest4 = make_shared<Interest>(command4);
  m_keyChain.signByIdentity(*interest4, normalId);
  // "normalId" is in "test" pib, can be trusted for some commands about "test".
  // Detail checking is needed, but it is not the job of Validator, OK.
  validator.validate(*interest4,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(false); });

  Name command5("/localhost/pib/test2/verb/param");
  shared_ptr<Interest> interest5 = make_shared<Interest>(command5);
  m_keyChain.signByIdentity(*interest5, normalId);
  // "normalId" is NOT in "test2" pib, cannot be trusted for any command about "test2", MUST fail
  validator.validate(*interest5,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(false); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(true); });

  db.deleteUser("test2");
  db.deleteUser("test");
  db.deleteUser("root");
}

BOOST_AUTO_TEST_CASE(AddNewUser)
{
  PibDb db("/tmp");
  PibValidator validator(db);
  db.onUserChanged += bind(&PibValidator::handleUserChange, &validator, _1);
  db.onKeyDeleted += bind(&PibValidator::handleKeyDeletion, &validator, _1, _2, _3);

  Name root("/localhost/pib/user");
  BOOST_REQUIRE(addIdentity(root, RsaKeyParams()));
  shared_ptr<IdentityCertificate> rootCert = getCertificateForIdentity(root);
  db.addRootUser(*rootCert);

  Name testUser("/localhost/pib/user/test");
  BOOST_REQUIRE(addIdentity(testUser, RsaKeyParams()));
  shared_ptr<IdentityCertificate> testUserCert = getCertificateForIdentity(testUser);
  db.addUser(*testUserCert);

  Name testUser2("/localhost/pib/user/test2");
  BOOST_REQUIRE(addIdentity(testUser2, RsaKeyParams()));
  shared_ptr<IdentityCertificate> testUser2Cert = getCertificateForIdentity(testUser2);

  PibUser pibUser;
  pibUser.setMgmtCert(*testUser2Cert);
  UpdateParam updateParam(pibUser);
  Name command1("/localhost/pib/test2/update");
  command1.append(updateParam.wireEncode());
  shared_ptr<Interest> interest1 = make_shared<Interest>(command1);
  m_keyChain.signByIdentity(*interest1, testUser2);
  // Self-registration is allowed. (Note: this is verification only, "test2" is NOT added yet). OK.
  validator.validate(*interest1,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(false); });

  shared_ptr<Interest> interest2 = make_shared<Interest>(command1);
  m_keyChain.signByIdentity(*interest2, testUser);
  // "test" is NOT allowed to register any other user as a new user, MUST fail.
  validator.validate(*interest2,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(false); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(true); });

  UpdateParam updateParam3(Name("/test/id"));
  Name command3("/localhost/pib/test2/update");
  command3.append(updateParam3.wireEncode());
  shared_ptr<Interest> interest3 = make_shared<Interest>(command3);
  m_keyChain.signByIdentity(*interest3, testUser2);
  // "test2" does not exist, MUST fail.
  validator.validate(*interest3,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(false); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(true); });

  DeleteParam deleteParam4(Name("/test/id"));
  Name command4("/localhost/pib/test2/delete");
  command4.append(deleteParam4.wireEncode());
  shared_ptr<Interest> interest4 = make_shared<Interest>(command4);
  m_keyChain.signByIdentity(*interest4, testUser2);
  // "test2" does not exist, MUST fail
  validator.validate(*interest4,
    [] (const shared_ptr<const Interest>&) { BOOST_CHECK(false); },
    [] (const shared_ptr<const Interest>&, const std::string&) { BOOST_CHECK(true); });

  db.deleteUser("test");
  db.deleteUser("root");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace test
} // namespace pib
} // namespace ndn

/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
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

#include "security/schema/schema-interpreter.hpp"
#include "identity-management-fixture.hpp"
#include "boost-test.hpp"
#include "security/schema/trust-anchor-container.hpp"
#include "security/schema/signer.hpp"
#include "util/io.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace security {
namespace tests {

BOOST_AUTO_TEST_SUITE(SecuritySchemaInterpreter)

BOOST_FIXTURE_TEST_CASE(Load, security::IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");
  Name identity1("/ndn/edu/ucla/another/anchor");
  identity1.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity1));
  Name certName1 = m_keyChain.getDefaultCertificateNameForIdentity(identity1);
  shared_ptr<IdentityCertificate> idCert1 = m_keyChain.getCertificate(certName1);
  io::save(*idCert1, "trust-anchor-2.cert");

  SchemaInterpreter schema;

  std::string SCHEMA =
    "interest-rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($1,$2)\n"
    "}\n"
    "rule\n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)<ucla>(<>)<>*\n"
    "  signer k2($1)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k2\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  file \"trust-anchor-1.cert\"\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k3\"\n"
    "  name (<>*)<ucla><another><anchor>\n"
    "  file \"trust-anchor-2.cert\"\n"
    "  refresh 1s\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  BOOST_CHECK_EQUAL(schema.getDataRules().size(), 1);
  BOOST_CHECK_EQUAL(schema.getInterestRules().size(), 1);
  BOOST_CHECK_EQUAL(schema.getStaticTrustAnchors().size(), 1);
  BOOST_CHECK_EQUAL(schema.getDynamicTrustAnchors().size(), 1);
  BOOST_CHECK_EQUAL(static_cast<bool>(schema.getCertificate(certName1.getPrefix(-1))), true);
  BOOST_CHECK(schema.getSigReq() != nullptr);

  const boost::filesystem::path CERT_PATH1 =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH1);
  const boost::filesystem::path CERT_PATH2 =
    (boost::filesystem::current_path() / std::string("trust-anchor-2.cert"));
  boost::filesystem::remove(CERT_PATH2);
}

BOOST_FIXTURE_TEST_CASE(CheckSignature, security::IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName1("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data1, identity));

  SchemaInterpreter schema;

  std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($1,$2)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  file \"trust-anchor-1.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  BOOST_CHECK_EQUAL(schema.checkSignature(data1->getSignature()), true);

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(CheckDataRule, security::IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName1("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data1, identity));

  SchemaInterpreter schema;

  std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($1,$2)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  file \"trust-anchor-1.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  BOOST_CHECK_EQUAL(schema.checkDataRule(dataName1,
                                         data1->getSignature().getKeyLocator().getName()),
                    true);
  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(CheckDataRule1, security::IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);

  Name dataName1("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data1, identity));

  SchemaInterpreter schema;

  std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($1,$2)\n"
    "}\n"
    "rule\n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  signer k2($1)\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  BOOST_CHECK_EQUAL(schema.checkDataRule(dataName1,
                                         data1->getSignature().getKeyLocator().getName()),
                    true);
}

BOOST_FIXTURE_TEST_CASE(DeriveSignerPatterns, security::IdentityManagementFixture)
{
  Name dataName1("/ndn/edu/ucla/qiuhan/cs/bh");

  Name anchor("/ndn/edu/ucla/key");
  anchor.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(anchor));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(anchor);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  SchemaInterpreter schema;

  std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($1,$2)|k2($1)\n"
    "}\n"
    "rule\n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)<ucla>(<>)<config><key><>*\n"
    "  signer k2($1)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k2\"\n"
    "  name (<>*)<ucla><key><>*\n"
    "  file \"trust-anchor-1.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  std::vector <std::pair <std::string, std::string> >signers1 = schema.deriveSignerPatternFromName(dataName1);
  BOOST_CHECK_EQUAL(signers1.size(), 2);
  BOOST_CHECK_EQUAL(signers1[0].first, "k1");
  BOOST_CHECK_EQUAL(signers1[0].second, "<ndn><edu><ucla><qiuhan><config><key><>*");
  BOOST_CHECK_EQUAL(signers1[1].first, "k2");
  BOOST_CHECK_EQUAL(signers1[1].second, "<ndn><edu><ucla><key><>*");
  std::vector <std::pair <std::string, std::string> >signers2 = schema.derivePatternFromRuleId("k1");
  BOOST_CHECK_EQUAL(signers2.size(), 1);
  BOOST_CHECK_EQUAL(signers2[0].first, "k2");
  BOOST_CHECK_EQUAL(signers2[0].second, "<ndn><edu><ucla><key><>*");

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(CheckAny, security::IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);

  Name dataName1("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data1, identity));

  SchemaInterpreter schema;

  std::string SCHEMA =
    "any true\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  BOOST_CHECK_EQUAL(schema.checkDataRule(dataName1,
                                         data1->getSignature().getKeyLocator().getName()),
                    true);

  SCHEMA =
    "any false\n";

  BOOST_REQUIRE_NO_THROW(schema.load(SCHEMA, CONFIG_PATH.native()));
  BOOST_CHECK_EQUAL(schema.checkDataRule(dataName1,
                                         data1->getSignature().getKeyLocator().getName()),
                    false);
}


BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace security
} // namespace ndn

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

#include "security/validator-schema.hpp"

#include "security/key-chain.hpp"
#include "util/io.hpp"
#include "util/scheduler.hpp"
#include "util/dummy-client-face.hpp"

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

#include "../identity-management-time-fixture.hpp"
#include "boost-test.hpp"

using namespace std;

namespace ndn {
namespace security {
namespace tests {

BOOST_AUTO_TEST_SUITE(SecurityValidatorSchema)

BOOST_FIXTURE_TEST_CASE(ValidateData, IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data = make_shared<Data>(dataName);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data, identity));

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

  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*data,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(ValidateData1, IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data = make_shared<Data>(dataName);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data, identity));

  std::string SCHEMA =
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<ucla>(<>)<cs><><>*\n"
    "  signer k1($2)|k2($1,$2)\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id \"k2\"\n"
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

  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*data,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(ValidateInterest, IdentityManagementFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name interestName("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Interest> interest = make_shared<Interest>(interestName);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*interest, identity));

  std::string SCHEMA =
    "interest-rule\n"
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

  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*interest,
                     [] (const shared_ptr<const Interest>&) { BOOST_CHECK(true); },
                     [] (const shared_ptr<const Interest>&, const string&) { BOOST_CHECK(false); });

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(ValidateAny, IdentityManagementTimeFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data = make_shared<Data>(dataName);

  std::string SCHEMA =
    "any true\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*data,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data, identity));

  validator.validate(*data,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_FIXTURE_TEST_CASE(AnchorWithTime, IdentityManagementTimeFixture)
{
  Name identity("/ndn/edu/ucla/qiuhan/config/key");
  identity.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity));
  Name certName = m_keyChain.getDefaultCertificateNameForIdentity(identity);
  shared_ptr<IdentityCertificate> idCert = m_keyChain.getCertificate(certName);
  io::save(*idCert, "trust-anchor-1.cert");

  Name dataName("/ndn/edu/ucla/qiuhan/cs/bh");
  shared_ptr<Data> data = make_shared<Data>(dataName);
  BOOST_REQUIRE_NO_THROW(m_keyChain.signByIdentity(*data, identity));

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

  Face face;
  ValidatorSchema validator(face);
  validator.load(SCHEMA, CONFIG_PATH.native());
  validator.validate(*data,
                     [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-1.cert"));
  boost::filesystem::remove(CERT_PATH);

  Name identity1("/ndn/edu/ucla/qiuhan/fake/key");
  identity1.appendVersion();
  BOOST_REQUIRE_NO_THROW(addIdentity(identity1));
  Name certName1 = m_keyChain.getDefaultCertificateNameForIdentity(identity1);
  shared_ptr<IdentityCertificate> idCert1 = m_keyChain.getCertificate(certName1);
  io::save(*idCert1, "trust-anchor-1.cert");

  advanceClocks(time::milliseconds(10), 200);

  validator.validate(*data,
                     [] (const shared_ptr<const Data>&) { BOOST_CHECK(false); },
                     [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(true); });

  boost::filesystem::remove(CERT_PATH);
}

struct FacesFixture : public security::IdentityManagementTimeFixture
{
  FacesFixture()
    : face1(util::makeDummyClientFace(io, {true, true}))
    , face2(util::makeDummyClientFace(io, {true, true}))
    , readInterestOffset1(0)
    , readDataOffset1(0)
    , readInterestOffset2(0)
    , readDataOffset2(0)
  {
  }

  bool
  passPacket()
  {
    bool hasPassed = false;

    checkFace(face1->sentInterests, readInterestOffset1, *face2, hasPassed);
    checkFace(face1->sentDatas, readDataOffset1, *face2, hasPassed);
    checkFace(face2->sentInterests, readInterestOffset2, *face1, hasPassed);
    checkFace(face2->sentInterests, readDataOffset2, *face1, hasPassed);

    return hasPassed;
  }

  template<typename Packet>
  void
  checkFace(std::vector<Packet>& receivedPackets,
            size_t& readPacketOffset,
            util::DummyClientFace& receiver,
            bool& hasPassed)
  {
    while (receivedPackets.size() > readPacketOffset) {
      receiver.receive(receivedPackets[readPacketOffset]);
      readPacketOffset++;
      hasPassed = true;
    }
  }

  ~FacesFixture()
  {
  }

public:
  shared_ptr<util::DummyClientFace> face1;
  shared_ptr<util::DummyClientFace> face2;

  size_t readInterestOffset1;
  size_t readDataOffset1;
  size_t readInterestOffset2;
  size_t readDataOffset2;
};

BOOST_FIXTURE_TEST_CASE(HierarchicalTrustModel, FacesFixture)
{
  std::vector<CertificateSubjectDescription> subjectDescription;

  Name root("/TestValidatorSchema");
  BOOST_REQUIRE_NO_THROW(addIdentity(root));
  Name rootCertName = m_keyChain.getDefaultCertificateNameForIdentity(root);
  shared_ptr<IdentityCertificate> rootCert = m_keyChain.getCertificate(rootCertName);
  io::save(*rootCert, "trust-anchor-6.cert");

  Name sld("/TestValidatorSchema/Hierarchical");
  BOOST_REQUIRE_NO_THROW(addIdentity(sld));
  advanceClocks(time::milliseconds(100));
  Name sldKeyName = m_keyChain.generateRsaKeyPairAsDefault(sld, true);
  shared_ptr<IdentityCertificate> sldCert =
    m_keyChain.prepareUnsignedIdentityCertificate(sldKeyName,
                                                  root,
                                                  time::system_clock::now(),
                                                  time::system_clock::now() + time::days(7300),
                                                  subjectDescription);
  m_keyChain.signByIdentity(*sldCert, root);
  m_keyChain.addCertificateAsIdentityDefault(*sldCert);

  Name nld("/TestValidatorSchema/Hierarchical/NextLevel");
  BOOST_REQUIRE_NO_THROW(addIdentity(nld));
  advanceClocks(time::milliseconds(100));
  Name nldKeyName = m_keyChain.generateRsaKeyPairAsDefault(nld, true);
  shared_ptr<IdentityCertificate> nldCert =
    m_keyChain.prepareUnsignedIdentityCertificate(nldKeyName,
                                                  sld,
                                                  time::system_clock::now(),
                                                  time::system_clock::now() + time::days(7300),
                                                  subjectDescription);
  m_keyChain.signByIdentity(*nldCert, sld);
  m_keyChain.addCertificateAsIdentityDefault(*nldCert);

  face1->setInterestFilter(sldCert->getName().getPrefix(-1),
    [&] (const InterestFilter&, const Interest&) { face1->put(*sldCert); },
    RegisterPrefixSuccessCallback(),
    [] (const Name&, const std::string&) {});

  face1->setInterestFilter(nldCert->getName().getPrefix(-1),
    [&] (const InterestFilter&, const Interest&) { face1->put(*nldCert); },
    RegisterPrefixSuccessCallback(),
    [] (const Name&, const std::string&) {});

  Name dataName1 = nld;
  shared_ptr<Data> data1 = make_shared<Data>(dataName1);
  BOOST_CHECK_NO_THROW(m_keyChain.signByIdentity(*data1, nld));

  Name dataName2("/ValidatorSchemaTest");
  dataName2.append("data1");
  shared_ptr<Data> data2 = make_shared<Data>(dataName2);
  BOOST_CHECK_NO_THROW(m_keyChain.signByIdentity(*data2, nld));


  const std::string CONFIG =
    "rule \n"
    "{\n"
    "  id \"k1\"\n"
    "  name (<>*)(<>)<KEY><>*\n"
    "  signer k1($1,null)|ac1()\n"
    "}\n"
    "rule\n"
    "{\n"
    "  id \"pkt\"\n"
    "  name (<>*)<>\n"
    "  signer k1($1,null)|ac1()\n"
    "}\n"
    "anchor\n"
    "{\n"
    "  id ac1\n"
    "  name <TestValidatorSchema><KEY><>*<ID-CERT><>*\n"
    "  file \"trust-anchor-6.cert\"\n"
    "}\n"
    "sig-req\n"
    "{\n"
    "  hash sha-256\n"
    "  signing rsa|ecdsa\n"
    "  key-size 112\n"
    "}\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-nfd.conf"));

  auto validator = make_shared<ValidatorSchema>(face2.get());
  validator->load(CONFIG, CONFIG_PATH.native());

  advanceClocks(time::milliseconds(2), 100);
  validator->validate(*data1,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(true); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(false); });

  do {
    advanceClocks(time::milliseconds(2), 10);
  } while (passPacket());

  validator->validate(*data2,
    [] (const shared_ptr<const Data>&) { BOOST_CHECK(false); },
    [] (const shared_ptr<const Data>&, const string&) { BOOST_CHECK(true); });

  do {
    advanceClocks(time::milliseconds(2), 10);
    } while (passPacket());

  const boost::filesystem::path CERT_PATH =
    (boost::filesystem::current_path() / std::string("trust-anchor-6.cert"));
  boost::filesystem::remove(CERT_PATH);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace security
} // namespace ndn

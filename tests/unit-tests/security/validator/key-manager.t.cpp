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

#include "security/validator/key-manager.hpp"
#include "util/dummy-client-face.hpp"

#include "../../unit-test-time-fixture.hpp"
#include "boost-test.hpp"

namespace ndn {
namespace security {
namespace validator {
namespace tests {

using namespace ndn::tests;

BOOST_AUTO_TEST_SUITE(Security)
BOOST_AUTO_TEST_SUITE(Validator)
BOOST_AUTO_TEST_SUITE(TestKeyManager)

const uint8_t sigInfo[] = {
0x16, 0x1b, // SignatureInfo
  0x1b, 0x01, // SignatureType
    0x03,
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74,
      0x08, 0x03,
        0x6b, 0x65, 0x79,
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
};

const uint8_t sigValue[] = {
0x17, 0x40, // SignatureValue
  0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
  0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
  0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
  0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
  0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b
};

class DummyKeyManager : public KeyManager
{
public:
  DummyKeyManager(Face* face)
    : KeyManager(face)
  {
  }

private:
  void
  preProcess(shared_ptr<KeyRequest>& req)
  {
  }
};

class KeyManagerFixture : public ndn::tests::UnitTestTimeFixture
{
public:
  KeyManagerFixture()
    : face1(util::makeDummyClientFace(io, {true, true}))
    , face2(util::makeDummyClientFace(io, {true, true}))
    , readInterestOffset1(0)
    , readDataOffset1(0)
    , readInterestOffset2(0)
    , readDataOffset2(0)
  {
    Block sigInfoBlock(sigInfo, sizeof(sigInfo));
    Block sigValueBlock(sigValue, sizeof(sigValue));

    Signature sig(sigInfoBlock, sigValueBlock);

    identity1 = Name("/TestKeyManager/First/KEY").appendVersion();
    cert1 = make_shared<Data>(identity1);
    cert1->setSignature(sig);
    cert1->wireEncode();
    interest1 = make_shared<Interest>(identity1.getPrefix(-1));

    identity2 = Name("/TestKeyManager/Second/KEY").appendVersion();
    cert2 = make_shared<Data>(identity2);
    cert2->setSignature(sig);
    cert2->wireEncode();
    
    interest2 = make_shared<Interest>(identity2.getPrefix(-1));

    face2->setInterestFilter(identity2.getPrefix(-1),
                             [&] (const InterestFilter&, const Interest&) { face2->put(*cert2); },
                             RegisterPrefixSuccessCallback(),
                             [] (const Name&, const std::string&) {});

    req1 = make_shared<KeyRequest>(*interest1, [](const shared_ptr<const Data>&) {},
                                   [](const shared_ptr<const Data>&, const std::string&){}, 1);
    req2 = make_shared<KeyRequest>(*interest2, [](const shared_ptr<const Data>&) {},
                                   [](const shared_ptr<const Data>&, const std::string&){}, 1);
  }

  bool
  passPacket()
  {
    bool hasPassed = false;

    checkFace(face1->sentInterests, readInterestOffset1, *face2, hasPassed);
    checkFace(face1->sentDatas, readDataOffset1, *face2, hasPassed);
    checkFace(face2->sentInterests, readInterestOffset2, *face1, hasPassed);
    checkFace(face2->sentDatas, readDataOffset2, *face1, hasPassed);

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

  ~KeyManagerFixture()
  {
  }

public:
  shared_ptr<util::DummyClientFace> face1;
  shared_ptr<util::DummyClientFace> face2;

  size_t readInterestOffset1;
  size_t readDataOffset1;
  size_t readInterestOffset2;
  size_t readDataOffset2;

  Name identity1;
  Name identity2;

  shared_ptr<Data> cert1;
  shared_ptr<Data> cert2;

  shared_ptr<Interest> interest1;
  shared_ptr<Interest> interest2;

  shared_ptr<KeyRequest> req1;
  shared_ptr<KeyRequest> req2;
};

BOOST_FIXTURE_TEST_CASE(Retrieve, KeyManagerFixture)
{
  auto keyManager = make_shared<DummyKeyManager>(face1.get());
  // Fetch certificate from network
  keyManager->retrieveCertificate(req1,
                                  [] (const Interest&, const Data&, shared_ptr<KeyRequest>&) {
                                    BOOST_CHECK(false);
                                  },
                                  [] (const Interest&, shared_ptr<KeyRequest>&) {
                                    BOOST_CHECK(true);
                                  });
  keyManager->retrieveCertificate(req2,
                                  [] (const Interest&, const Data&, shared_ptr<KeyRequest>&) {
                                    BOOST_CHECK(true);
                                  },
                                  [] (const Interest&, shared_ptr<KeyRequest>&) {
                                    BOOST_CHECK(false);
                                  });

  // Time is long enough for the time out
  for (int i = 0 ; i < 10; ++i) {
    advanceClocks(time::milliseconds(20), 100);
    passPacket();
  }

  // Retrieve certificate from unverified cache
  keyManager->loadUnverifiedKey(cert1);
  auto key = keyManager->retrieveTrustedCert(*interest1);
  BOOST_CHECK(key == nullptr);
  keyManager->retrieveCertificate(req1,
                                  [] (const Interest&, const Data&, shared_ptr<KeyRequest>&) {
                                    BOOST_CHECK(true);
                                  },
                                  [] (const Interest&, shared_ptr<KeyRequest>&) {
                                    BOOST_CHECK(false);
                                  });

  for (int i = 0 ; i < 10; i ++) {
    advanceClocks(time::milliseconds(20), 100);
    passPacket();
  }

  // Retrieve certificate from verified key cache
  time::system_clock::TimePoint expireTime = time::system_clock::now() + time::seconds(10);
  keyManager->loadVerifiedKey(cert1, expireTime);
  key = keyManager->retrieveTrustedCert(*interest1);
  BOOST_CHECK(key != nullptr);

  // Retrive certificate from trust anchor cache
  keyManager->loadAnchor(cert2);
  key = keyManager->retrieveTrustedCert(*interest2);
  BOOST_CHECK(key != nullptr);
}

BOOST_AUTO_TEST_SUITE_END() // TestKeyManager
BOOST_AUTO_TEST_SUITE_END() // Validator
BOOST_AUTO_TEST_SUITE_END() // Security

} // namespace tests
} // namespace validator
} // namespace security
} // namespace ndn


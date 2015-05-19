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

#include "validator-schema.hpp"
#include "certificate-cache-ttl.hpp"
#include "../util/io.hpp"

#include <boost/filesystem.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/algorithm/string.hpp>

namespace ndn {
namespace security {

const shared_ptr<CertificateCache> ValidatorSchema::DEFAULT_CERTIFICATE_CACHE;
const time::milliseconds ValidatorSchema::DEFAULT_GRACE_INTERVAL(3000);
const time::system_clock::Duration ValidatorSchema::DEFAULT_KEY_TIMESTAMP_TTL = time::hours(1);

ValidatorSchema::ValidatorSchema(Face* face,
                                 const shared_ptr<CertificateCache>& certificateCache,
                                 const time::milliseconds& graceInterval,
                                 const size_t stepLimit,
                                 const size_t maxTrackedKeys,
                                 const time::system_clock::Duration& keyTimestampTtl)
  : Validator(face)
  , m_shouldValidate(true)
  , m_stepLimit(stepLimit)
  , m_certificateCache(certificateCache)
  , m_graceInterval(graceInterval < time::milliseconds::zero() ?
                    DEFAULT_GRACE_INTERVAL : graceInterval)
  , m_maxTrackedKeys(maxTrackedKeys)
  , m_keyTimestampTtl(keyTimestampTtl)
  , m_schemaInterpreter(make_shared<SchemaInterpreter>())
{
  if (!static_cast<bool>(m_certificateCache) && face != nullptr)
    m_certificateCache = make_shared<CertificateCacheTtl>(ref(face->getIoService()));
}

ValidatorSchema::ValidatorSchema(Face& face,
                                 const shared_ptr<CertificateCache>& certificateCache,
                                 const time::milliseconds& graceInterval,
                                 const size_t stepLimit,
                                 const size_t maxTrackedKeys,
                                 const time::system_clock::Duration& keyTimestampTtl)
  : Validator(face)
  , m_shouldValidate(true)
  , m_stepLimit(stepLimit)
  , m_certificateCache(certificateCache)
  , m_graceInterval(graceInterval < time::milliseconds::zero() ?
                    DEFAULT_GRACE_INTERVAL : graceInterval)
  , m_maxTrackedKeys(maxTrackedKeys)
  , m_keyTimestampTtl(keyTimestampTtl)
  , m_schemaInterpreter(make_shared<SchemaInterpreter>())
{
  if (!static_cast<bool>(m_certificateCache))
    m_certificateCache = make_shared<CertificateCacheTtl>(ref(face.getIoService()));
}

void
ValidatorSchema::load(const std::string& filename)
{
  std::ifstream inputFile;
  inputFile.open(filename.c_str());
  if (!inputFile.good() || !inputFile.is_open()) {
    std::string msg = "Failed to read configuration file: ";
    msg += filename;
    throw Error(msg);
  }
  load(inputFile, filename);
  inputFile.close();
}

void
ValidatorSchema::load(const std::string& input, const std::string& filename)
{
  std::istringstream inputStream(input);
  load(inputStream, filename);
}


void
ValidatorSchema::load(std::istream& input, const std::string& filename)
{
  m_schemaInterpreter->load(input, filename);
  m_shouldValidate = m_schemaInterpreter->getCheckFlag();
}

void
ValidatorSchema::reset()
{
  if (static_cast<bool>(m_certificateCache))
    m_certificateCache->reset();
  m_schemaInterpreter->reset();
  m_shouldValidate = true;
}

bool
ValidatorSchema::isEmpty()
{
  if ((!static_cast<bool>(m_certificateCache) || m_certificateCache->isEmpty()) &&
      m_schemaInterpreter->isEmpty())
    return true;
  return false;
}

void
ValidatorSchema::checkPolicy(const Data& data,
                             int nSteps,
                             const OnDataValidated& onValidated,
                             const OnDataValidationFailed& onValidationFailed,
                             std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  if (!m_shouldValidate)
    return onValidated(data.shared_from_this());

  const Signature& signature = data.getSignature();

  if (!m_schemaInterpreter->checkSignature(signature))
    return onValidationFailed(data.shared_from_this(), "Does not satisfy signature requirement!");

  if (!m_schemaInterpreter->checkDataRule(data.getName(),
                                          signature.getKeyLocator().getName()))
    return onValidationFailed(data.shared_from_this(), "No rule matched!");

  checkSignature(data, signature, nSteps,
                 onValidated, onValidationFailed, nextSteps);
}

void
ValidatorSchema::checkPolicy(const Interest& interest,
                             int nSteps,
                             const OnInterestValidated& onValidated,
                             const OnInterestValidationFailed& onValidationFailed,
                             std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  if (!m_shouldValidate)
    return onValidated(interest.shared_from_this());

  // If interestName has less than 4 name components,
  // it is definitely not a signed interest.
  if (interest.getName().size() < signed_interest::MIN_LENGTH)
    return onValidationFailed(interest.shared_from_this(),
                              "Interest is not signed: " + interest.getName().toUri());

  try {
    const Name& interestName = interest.getName();
    Signature signature(interestName[signed_interest::POS_SIG_INFO].blockFromValue(),
                        interestName[signed_interest::POS_SIG_VALUE].blockFromValue());

    if (!signature.hasKeyLocator())
      return onValidationFailed(interest.shared_from_this(),
                                "No valid KeyLocator");

    const KeyLocator& keyLocator = signature.getKeyLocator();

    if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
      return onValidationFailed(interest.shared_from_this(),
                                "Key Locator is not a name");

    Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocator.getName());

    if (!m_schemaInterpreter->checkSignature(signature))
      return onValidationFailed(interest.shared_from_this(),
                                "Does not satisfy signature requirement!");

    if (!m_schemaInterpreter->checkInterestRule(interestName, keyLocator.getName()))
      return onValidationFailed(interest.shared_from_this(), "No rule matched!");

    checkTimestamp(interest.shared_from_this(), keyName, onValidated, onValidationFailed);
    checkSignature<Interest, OnInterestValidated, OnInterestValidationFailed>
      (interest, signature, nSteps,
       bind(&ValidatorSchema::checkTimestamp, this, _1,
            keyName, onValidated, onValidationFailed),
       onValidationFailed,
       nextSteps);
  }
  catch (Signature::Error& e) {
    return onValidationFailed(interest.shared_from_this(),
                              "No valid signature");
  }
  catch (KeyLocator::Error& e) {
    return onValidationFailed(interest.shared_from_this(),
                              "No valid KeyLocator");
  }
  catch (IdentityCertificate::Error& e) {
    return onValidationFailed(interest.shared_from_this(),
                              "Cannot determine the signing key");
  }

  catch (tlv::Error& e) {
    return onValidationFailed(interest.shared_from_this(),
                              "Cannot decode signature");
  }
}

void
ValidatorSchema::checkTimestamp(const shared_ptr<const Interest>& interest,
                                const Name& keyName,
                                const OnInterestValidated& onValidated,
                                const OnInterestValidationFailed& onValidationFailed)
{
  const Name& interestName = interest->getName();
  time::system_clock::TimePoint interestTime;

  try {
    interestTime =
      time::fromUnixTimestamp(
        time::milliseconds(interestName.get(-signed_interest::MIN_LENGTH).toNumber()));
  }
  catch (tlv::Error& e) {
    return onValidationFailed(interest,
                              "Cannot decode signature related TLVs");
  }

  time::system_clock::TimePoint currentTime = time::system_clock::now();

  LastTimestampMap::iterator timestampIt = m_lastTimestamp.find(keyName);
  if (timestampIt == m_lastTimestamp.end()) {
    if (!(currentTime - m_graceInterval <= interestTime &&
          interestTime <= currentTime + m_graceInterval))
      return onValidationFailed(interest,
                                "The command is not in grace interval: " +
                                interest->getName().toUri());
  }
  else {
    if (interestTime < timestampIt->second)
      return onValidationFailed(interest,
                                "The command is outdated: " +
                                interest->getName().toUri());
  }

  //Update timestamp
  if (timestampIt == m_lastTimestamp.end()) {
    cleanOldKeys();
    m_lastTimestamp[keyName] = interestTime;
  }
  else {
    timestampIt->second = interestTime;
  }

  return onValidated(interest);
}

void
ValidatorSchema::cleanOldKeys()
{
  if (m_lastTimestamp.size() < m_maxTrackedKeys)
    return;

  LastTimestampMap::iterator timestampIt = m_lastTimestamp.begin();
  LastTimestampMap::iterator end = m_lastTimestamp.end();

  time::system_clock::TimePoint now = time::system_clock::now();
  LastTimestampMap::iterator oldestKeyIt = m_lastTimestamp.begin();
  time::system_clock::TimePoint oldestTimestamp = oldestKeyIt->second;

  while (timestampIt != end) {
    if (now - timestampIt->second > m_keyTimestampTtl) {
      LastTimestampMap::iterator toDelete = timestampIt;
      timestampIt++;
      m_lastTimestamp.erase(toDelete);
      continue;
    }

    if (timestampIt->second < oldestTimestamp) {
      oldestTimestamp = timestampIt->second;
      oldestKeyIt = timestampIt;
    }

    timestampIt++;
  }

  if (m_lastTimestamp.size() >= m_maxTrackedKeys)
    m_lastTimestamp.erase(oldestKeyIt);
}

template<class Packet, class OnValidated, class OnFailed>
void
ValidatorSchema::checkSignature(const Packet& packet,
                                const Signature& signature,
                                size_t nSteps,
                                const OnValidated& onValidated,
                                const OnFailed& onValidationFailed,
                                std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  if (signature.getType() == tlv::DigestSha256) {
    DigestSha256 sigSha256(signature);

    if (verifySignature(packet, sigSha256))
      return onValidated(packet.shared_from_this());
    else
      return onValidationFailed(packet.shared_from_this(),
                                "Sha256 Signature cannot be verified!");
  }

  try {
    switch (signature.getType()) {
    case tlv::SignatureSha256WithRsa:
    case tlv::SignatureSha256WithEcdsa:
      {
        if (!signature.hasKeyLocator()) {
          return onValidationFailed(packet.shared_from_this(),
                                    "Missing KeyLocator in SignatureInfo");
        }
        break;
      }
    default:
      return onValidationFailed(packet.shared_from_this(),
                              "Unsupported signature type");
    }
  }
  catch (KeyLocator::Error& e) {
    return onValidationFailed(packet.shared_from_this(),
                              "Cannot decode KeyLocator in public key signature");
  }
  catch (tlv::Error& e) {
    return onValidationFailed(packet.shared_from_this(),
                              "Cannot decode public key signature");
  }


  if (signature.getKeyLocator().getType() != KeyLocator::KeyLocator_Name) {
    return onValidationFailed(packet.shared_from_this(), "Unsupported KeyLocator type");
  }

  const Name& keyLocatorName = signature.getKeyLocator().getName();

  shared_ptr<const Certificate> trustedCert;

  m_schemaInterpreter->refreshAnchors();

  trustedCert = m_schemaInterpreter->getCertificate(keyLocatorName);
  if (trustedCert == nullptr && static_cast<bool>(m_certificateCache))
    trustedCert = m_certificateCache->getCertificate(keyLocatorName);

  if (static_cast<bool>(trustedCert)) {
    if (verifySignature(packet, signature, trustedCert->getPublicKeyInfo())) {
      return onValidated(packet.shared_from_this());
    }
    else
      return onValidationFailed(packet.shared_from_this(),
                                "Cannot verify signature");
  }
  else {
    if (m_stepLimit == nSteps)
      return onValidationFailed(packet.shared_from_this(),
                                "Maximum steps of validation reached");

    OnDataValidated onCertValidated =
      bind(&ValidatorSchema::onCertValidated<Packet, OnValidated, OnFailed>,
           this, _1, packet.shared_from_this(), onValidated, onValidationFailed);

    OnDataValidationFailed onCertValidationFailed =
      bind(&ValidatorSchema::onCertFailed<Packet, OnFailed>,
           this, _1, _2, packet.shared_from_this(), onValidationFailed);

    Interest certInterest(keyLocatorName);

    shared_ptr<ValidationRequest> nextStep =
      make_shared<ValidationRequest>(certInterest,
                                     onCertValidated,
                                     onCertValidationFailed,
                                     1, nSteps + 1);

    nextSteps.push_back(nextStep);
    return;
  }

  return onValidationFailed(packet.shared_from_this(), "Unsupported Signature Type");
}

template<class Packet, class OnValidated, class OnFailed>
void
ValidatorSchema::onCertValidated(const shared_ptr<const Data>& signCertificate,
                                 const shared_ptr<const Packet>& packet,
                                 const OnValidated& onValidated,
                                 const OnFailed& onValidationFailed)
{
  if (signCertificate->getContentType() != tlv::ContentType_Key)
    return onValidationFailed(packet,
                              "Cannot retrieve signer's cert: " +
                              signCertificate->getName().toUri());

  shared_ptr<IdentityCertificate> certificate;
  try {
    certificate = make_shared<IdentityCertificate>(*signCertificate);
  }
  catch (tlv::Error&) {
    return onValidationFailed(packet,
                              "Cannot decode signer's cert: " +
                              signCertificate->getName().toUri());
  }

  if (!certificate->isTooLate() && !certificate->isTooEarly()) {
    if (static_cast<bool>(m_certificateCache))
      m_certificateCache->insertCertificate(certificate);

    if (verifySignature(*packet, certificate->getPublicKeyInfo()))
      return onValidated(packet);
    else
      return onValidationFailed(packet,
                                "Cannot verify signature: " +
                                packet->getName().toUri());
  }
  else {
    return onValidationFailed(packet,
                              "Signing certificate " +
                              signCertificate->getName().toUri() +
                              " is no longer valid.");
  }
}

template<class Packet, class OnFailed>
void
ValidatorSchema::onCertFailed(const shared_ptr<const Data>& signCertificate,
                              const std::string& failureInfo,
                              const shared_ptr<const Packet>& packet,
                              const OnFailed& onValidationFailed)
{
  onValidationFailed(packet, failureInfo);
}

} // namespace security
} // namespace ndn

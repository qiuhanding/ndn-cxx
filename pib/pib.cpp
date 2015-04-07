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

#include "pib.hpp"

#include "security/pib/pib-encoding.hpp"
#ifdef NDN_CXX_HAVE_OSX_SECURITY
#include "security/sec-tpm-osx.hpp"
#endif // NDN_CXX_HAVE_OSX_SECURITY
#include "security/sec-tpm-file.hpp"
#include "util/io.hpp"
#include "util/crypto.hpp"
#include "util/concepts.hpp"

namespace ndn {
namespace pib {

using std::string;
using std::vector;
using std::set;

const Name Pib::PIB_PREFIX("/localhost/pib");
const Name Pib::EMPTY_SIGNER_NAME;
const name::Component Pib::MGMT_LABEL("mgmt");

static inline std::tuple<std::string/*type*/, std::string/*location*/>
parseTpmLocator(const std::string& tpmLocator)
{
  size_t pos = tpmLocator.find(':');
  if (pos != std::string::npos) {
    return std::make_tuple(tpmLocator.substr(0, pos),
                           tpmLocator.substr(pos + 1));
  }
  else {
    return std::make_tuple(tpmLocator, "");
  }
}

Pib::Pib(Face& face,
         const std::string& dbDir,
         const std::string& tpmLocator,
         const std::string& owner)
  : m_db(dbDir)
  , m_tpm(nullptr)
  , m_owner(owner)
  , m_validator(m_db)
  , m_face(face)
  , m_certPublisher(m_face, m_db)
{
  if (!m_db.getOwnerName().empty() && m_db.getOwnerName() != owner)
    throw Error("owner argument differs from OwnerName in database");

  if (!m_db.getTpmLocator().empty() && m_db.getTpmLocator() != tpmLocator)
    throw Error("tpmLocator argument differs from TpmLocator in database");

  initializeTpm(tpmLocator);
  initializeMgmtCert();
  m_db.setTpmLocator(tpmLocator);

  registerPrefix();
}

Pib::~Pib()
{
  m_face.unsetInterestFilter(m_pibMgmtFilterId);
  m_face.unsetInterestFilter(m_pibPrefixId);

}

void
Pib::initializeTpm(const string& tpmLocator)
{
  string tpmScheme, tpmLocation;
  std::tie(tpmScheme, tpmLocation) = parseTpmLocator(tpmLocator);

  if (tpmScheme == "tpm-file" || tpmScheme == "file") {
    m_tpm = unique_ptr<SecTpm>(new SecTpmFile(tpmLocation));
  }
#ifdef NDN_CXX_HAVE_OSX_SECURITY
  else if (tpmScheme == "tpm-osxkeychain" || tpmScheme == "osx-keychain") {
    m_tpm = unique_ptr<SecTpm>(new SecTpmOsx(tpmLocation));
  }
#endif
  else
    throw Error("Cannot initialize TPM: tpm is not supported");
}

void
Pib::initializeMgmtCert()
{
  shared_ptr<IdentityCertificate> mgmtCert = m_db.getMgmtCertificate();

  if (mgmtCert == nullptr ||
      !m_tpm->doesKeyExistInTpm(mgmtCert->getPublicKeyName(), KEY_CLASS_PRIVATE)) {
    // If mgmt cert is set, or corresponding private key of the current mgmt cert is missing,
    // generate new mgmt cert

    // key name: /localhost/pib/[UserName]/mgmt/dsk-...
    Name mgmtKeyName = PIB_PREFIX;
    mgmtKeyName.append(m_owner).append(MGMT_LABEL);
    std::ostringstream oss;
    oss << "dsk-" << time::toUnixTimestamp(time::system_clock::now()).count();
    mgmtKeyName.append(oss.str());

    // self-sign pib root key
    m_mgmtCert = prepareCertificate(mgmtKeyName, RsaKeyParams(),
                                    time::system_clock::now(),
                                    time::system_clock::now() + time::days(7300));

    // update management certificate in database
    m_db.updateMgmtCertificate(*m_mgmtCert);
  }
  else
    m_mgmtCert = mgmtCert;
}

shared_ptr<IdentityCertificate>
Pib::prepareCertificate(const Name& keyName, const KeyParams& keyParams,
                        const time::system_clock::TimePoint& notBefore,
                        const time::system_clock::TimePoint& notAfter,
                        const Name& signerName)
{
  // Generate mgmt key
  m_tpm->generateKeyPairInTpm(keyName, keyParams);
  shared_ptr<PublicKey> publicKey = m_tpm->getPublicKeyFromTpm(keyName);

  // Set mgmt cert
  auto certificate = make_shared<IdentityCertificate>();
  Name certName = keyName.getPrefix(-1);
  certName.append("KEY").append(keyName.get(-1)).append("ID-CERT").appendVersion();
  certificate->setName(certName);
  certificate->setNotBefore(notBefore);
  certificate->setNotAfter(notAfter);
  certificate->setPublicKeyInfo(*publicKey);
  CertificateSubjectDescription subjectName(oid::ATTRIBUTE_NAME, keyName.getPrefix(-1).toUri());
  certificate->addSubjectDescription(subjectName);
  certificate->encode();


  Name signingKeyName;
  KeyLocator keyLocator;
  if (signerName == EMPTY_SIGNER_NAME) {
    // Self-sign mgmt cert
    keyLocator = KeyLocator(certificate->getName().getPrefix(-1));
    signingKeyName = keyName;
  }
  else {
    keyLocator = KeyLocator(signerName.getPrefix(-1));
    signingKeyName = IdentityCertificate::certificateNameToPublicKeyName(signerName);
  }

  SignatureSha256WithRsa signature(keyLocator);
  certificate->setSignature(signature);
  EncodingBuffer encoder;
  certificate->wireEncode(encoder, true);
  Block signatureValue = m_tpm->signInTpm(encoder.buf(), encoder.size(),
                                          signingKeyName, DIGEST_ALGORITHM_SHA256);
  certificate->wireEncode(encoder, signatureValue);

  return certificate;
}

void
Pib::registerPrefix()
{
  // register pib prefix
  Name pibPrefix = PIB_PREFIX;
  pibPrefix.append(m_owner);
  m_face.registerPrefix(pibPrefix,
                        [] (const Name& name) {},
                        [] (const Name& name, const string& msg) {
                          throw Error("cannot register pib prefix");
                        });

  // set interest filter for management certificate
  m_pibMgmtFilterId =
    m_face.setInterestFilter(Name(pibPrefix).append(MGMT_LABEL),
                             [this] (const InterestFilter&, const Interest& interest) {
                               if (m_mgmtCert != nullptr) {
                                 m_face.put(*m_mgmtCert);
                               }
                             });
}

} // namespace pib
} // namespace ndn

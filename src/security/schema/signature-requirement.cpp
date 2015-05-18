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

#include "signature-requirement.hpp"

#include "../signature-sha256-with-rsa.hpp"
#include "../signature-sha256-with-ecdsa.hpp"
#include "../digest-sha256.hpp"
#include <boost/algorithm/string.hpp>

namespace ndn {
namespace security {

SignatureRequirement::SignatureRequirement(const SchemaSection& schemaSection)
{
  SchemaSection::const_iterator propertyIt = schemaSection.begin();

  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first, "hash"))
    throw Error("Expect <sig-req.hash>");

  std::string hash = propertyIt->second.data();
  propertyIt++;

  if (!boost::iequals(hash, "sha-256"))
    throw Error("Do not support hash other than Sha256");

  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first, "signing"))
    throw Error("Expect <sig-req.signing>");

  std::string signing = propertyIt->second.data();
  propertyIt++;

  if (boost::iequals(signing, "null")) {
    m_signingPolicies.insert(tlv::DigestSha256);
    m_signingPolicies.insert(tlv::SignatureSha256WithRsa);
    m_signingPolicies.insert(tlv::SignatureSha256WithEcdsa);
  }
  else {
    std::remove_if(signing.begin(),
                   signing.end(),
                   [](char x){return std::isspace(x);});
    size_t split = signing.find('|');
    size_t start = 0;
    while (start != std::string::npos) {
      std::string policy;
      if (split == std::string::npos) {
        policy = signing.substr(start);
        start = split;
      }
      else {
        policy = signing.substr(start, split-start);
        start = split + 1;
        split = signing.find('|', start);
      }
      if (boost::iequals(policy, "rsa"))
        m_signingPolicies.insert(tlv::SignatureSha256WithRsa);
      else if (boost::iequals(policy, "ecdsa"))
        m_signingPolicies.insert(tlv::SignatureSha256WithEcdsa);
      else
        throw Error("Do not support other signing policy");
    }
  }

  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first, "key-size"))
    throw Error("Expect <sig-req.key-size>");

  m_keySize = stoi(propertyIt->second.data());
  propertyIt++;

  if (propertyIt != schemaSection.end())
    throw Error("Expect the end of sig-req");
}

bool
SignatureRequirement::checkRsaKeySize(size_t length)
{
  if (m_keySize >= 112 && m_keySize < 128)
    return length >= 256;
  if (m_keySize >= 128 && m_keySize < 192)
    return length >= 384;
  if (m_keySize >= 192 && m_keySize < 256)
    return length >= 960;
  if (m_keySize >= 256)
    return length >= 1920;
  return false;
}

bool
SignatureRequirement::check(const Signature& sig)
{
  if (m_signingPolicies.find(sig.getType()) == m_signingPolicies.end())
    return false;
  if (sig.getType() == tlv::DigestSha256)
    return true;

  size_t keySize = sig.getValue().value_size();
  switch (sig.getType()) {
  case tlv::SignatureSha256WithRsa: {
    return checkRsaKeySize(keySize);
  }
  case tlv::SignatureSha256WithEcdsa: {
    // currently we do not check the keysize of ecdsa
    return true;
  }
  default:
    return false;
  }
}

} // namespace security
} // namespace ndn

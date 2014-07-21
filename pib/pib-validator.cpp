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

#include "pib-validator.hpp"
#include "security/pib/pib-common.hpp"
#include "security/pib/update-param.hpp"
#include <set>
#include <string>

namespace ndn {
namespace pib {

using std::set;
using std::string;

PibValidator::PibValidator(const PibDb& db, size_t maxCacheSize)
  : m_db(db)
{
  m_keyCache["root"] = make_shared<UserKeyCache>();

  const_cast<PibDb&>(m_db).onUserChanged += bind(&PibValidator::handleUserChange, this, _1);
  const_cast<PibDb&>(m_db).onKeyDeleted += bind(&PibValidator::handleKeyDeletion, this, _1, _2, _3);

  set<string> users;
  m_db.listUsers(users);

  for (const auto& user : users) {
    shared_ptr<IdentityCertificate> mgmtCertificate = m_db.getUserMgmtCertificate(user);
    if (static_cast<bool>(mgmtCertificate)) {
      auto userKeyCache = make_shared<UserKeyCache>();
      userKeyCache->mgmtCertificate = mgmtCertificate;
      m_keyCache[user] = userKeyCache;
    }
  }
}

void
PibValidator::checkPolicy(const Interest& interest,
                          int nSteps,
                          const OnInterestValidated& onValidated,
                          const OnInterestValidationFailed& onValidationFailed,
                          std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  const Name& interestName = interest.getName();

  if (interestName.size() != SIGNED_PIB_INTEREST_SIZE) {
    return onValidationFailed(interest.shared_from_this(),
                              "Interest is not signed: " + interest.getName().toUri());
  }

  // Check if the user exists in PIB
  string user = interestName.get(OFFSET_USER).toUri();
  PublicKeyCache::const_iterator userIt = m_keyCache.find(user);
  if (userIt == m_keyCache.end()) {
    // In most cases if the user does not exist, the command is invalid.
    // The only exception is adding a new user.
    string verb = interestName.get(OFFSET_VERB).toUri();
    if (verb == "update") {
      try {
        UpdateParam updateParam;
        updateParam.wireDecode(interestName.get(OFFSET_PARAM).blockFromValue());
        if (updateParam.getEntityType() != tlv::pib::User) {
          return onValidationFailed(interest.shared_from_this(), "User does not exist(2): " + user);
        }
        else {
          // If it is adding new user, then the command should be self-signed
          try {
            Signature signature(interestName[OFFSET_SIG_INFO].blockFromValue(),
                                interestName[OFFSET_SIG_VALUE].blockFromValue());
            const PublicKey& key =
              updateParam.getUser().getMgmtCert().getPublicKeyInfo();
            if (verifySignature(interest, signature, key))
              onValidated(interest.shared_from_this());
            else
              onValidationFailed(interest.shared_from_this(),
                                 "PibValidator::checkPolicy: Cannot verify signature");
            return;
          }
          catch (tlv::Error&) {
            return onValidationFailed(interest.shared_from_this(),
                                      "Cannot decode signature");
          }
        }
      }
      catch (tlv::Error&) {
        return onValidationFailed(interest.shared_from_this(), "Cannot decode parameter");
      }
    }
    else {
      return onValidationFailed(interest.shared_from_this(), "User does not exist: " + user);
    }
  }
  shared_ptr<const UserKeyCache> userKeyCache = userIt->second;

  // Verify signature
  try {
    Signature signature(interestName[OFFSET_SIG_INFO].blockFromValue(),
                        interestName[OFFSET_SIG_VALUE].blockFromValue());
    // KeyLocator is required to contain the name of signing certificate (w/o version)
    if (!signature.hasKeyLocator())
      return onValidationFailed(interest.shared_from_this(),
                                "No valid KeyLocator");
    const KeyLocator& keyLocator = signature.getKeyLocator();
    if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
      return onValidationFailed(interest.shared_from_this(),
                                "Key Locator is not a name");

    // Check if PIB has the corresponding public key
    shared_ptr<PublicKey> publicKey;


    if (keyLocator.getName() == getRootKeyCache()->mgmtCertificate->getName().getPrefix(-1)) {
      // the signing key is the root mgmt key.
      publicKey = make_shared<PublicKey>(getRootKeyCache()->mgmtCertificate->getPublicKeyInfo());
    }
    else if (keyLocator.getName() == userKeyCache->mgmtCertificate->getName().getPrefix(-1)) {
      // the signing key is user's mgmt key.
      publicKey = make_shared<PublicKey>(userKeyCache->mgmtCertificate->getPublicKeyInfo());
    }
    else {
      // the signing key is normal key.
      Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocator.getName());

      shared_ptr<PublicKey> key = userKeyCache->regularKeys.find(keyName);
      if (static_cast<bool>(key)) {
        // the signing key is cached.
        publicKey = key;
      }
      else {
        // the signing key is not cached.
        publicKey = m_db.getKey(user, keyName.getPrefix(-1), keyName[-1]);
        if (!static_cast<bool>(publicKey)) {
          // the signing key does not exist in PIB.
          return onValidationFailed(interest.shared_from_this(),
                                    "Public key is not trusted");
        }
        else {
          // the signing key is retrieved from PIB.
          BOOST_ASSERT(static_cast<bool>(m_keyCache[user]));
          m_keyCache[user]->regularKeys.insert(keyName, publicKey);
        }
      }
    }

    if (verifySignature(interest, signature, *publicKey))
      onValidated(interest.shared_from_this());
    else
      onValidationFailed(interest.shared_from_this(),
                         "PibValidator::checkPolicy: Cannot verify signature");

  }
  catch (KeyLocator::Error&) {
    return onValidationFailed(interest.shared_from_this(),
                              "No valid KeyLocator");
  }
  catch (Signature::Error&) {
    return onValidationFailed(interest.shared_from_this(),
                              "No valid signature");
  }
  catch (tlv::Error&) {
    return onValidationFailed(interest.shared_from_this(),
                              "Cannot decode signature");
  }
  catch (IdentityCertificate::Error&) {
    return onValidationFailed(interest.shared_from_this(),
                              "Cannot determine the signing key");
  }
}

void
PibValidator::checkPolicy(const Data& data,
                          int nSteps,
                          const OnDataValidated& onValidated,
                          const OnDataValidationFailed& onValidationFailed,
                          std::vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  // Pib does not express any interest, therefor should not validate any data.
  onValidationFailed(data.shared_from_this(),
                     "PibValidator Should not receive data packet");
}

shared_ptr<PibValidator::UserKeyCache>
PibValidator::getRootKeyCache()
{
  return m_keyCache["root"];
}


void
PibValidator::handleUserChange(const std::string& user)
{
  if (m_db.hasUser(user)) {
    auto userKeyCacheIt = m_keyCache.find(user);
    if (userKeyCacheIt == m_keyCache.end()) {
      auto userKeyCache = make_shared<UserKeyCache>();
      userKeyCache->mgmtCertificate = m_db.getUserMgmtCertificate(user);
      m_keyCache[user] = userKeyCache;
    }
    else {
      BOOST_ASSERT(static_cast<bool>(userKeyCacheIt->second));
      userKeyCacheIt->second->mgmtCertificate = m_db.getUserMgmtCertificate(user);
    }
  }
  else
    m_keyCache.erase(user);
}

void
PibValidator::handleKeyDeletion(const std::string& user, const Name& identity,
                                const name::Component& keyId)
{
  if (!m_db.hasKey(user, identity, keyId)) {
    Name keyName = identity;
    keyName.append(keyId);
    BOOST_ASSERT(static_cast<bool>(m_keyCache[user]));
    m_keyCache[user]->regularKeys.erase(keyName);
  }
}

} // namespace pib
} // namespace ndn

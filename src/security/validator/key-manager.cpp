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

#include "key-manager.hpp"

namespace ndn {
namespace security {
namespace validator {

KeyManager::KeyManager(Face* face)
  : m_face(face)
{
}

KeyManager::~KeyManager() = default;

shared_ptr<const Data>
KeyManager::retrieveTrustedCert(const Interest& interest)
{
  auto anchor = m_anchorCache.find(interest);
  if (anchor != nullptr) {
    return anchor;
  }

  auto key = m_verifiedKeyCache.find(interest);
  return key;
}

void
KeyManager::retrieveCertificate(shared_ptr<KeyRequest>& req,
                                const RetrievalSuccessCallback& onRetrieval,
                                const RetrievalFailureCallback& onFailure)
{
  auto cert = m_unVerifiedKeyCache.find(req->m_interest);
  if (cert != nullptr)
    return onRetrieval(req->m_interest, *cert, req);
  if (m_face != nullptr)
    fetchKeyFromNetwork(req, onRetrieval, onFailure);
  else
    onFailure(req->m_interest, req);
}

void
KeyManager::fetchKeyFromNetwork(shared_ptr<KeyRequest>& req,
                                const RetrievalSuccessCallback& onRetrieval,
                                const RetrievalFailureCallback& onFailure)
{
  preProcess(req);
  if (m_face != nullptr) {
    DataCallback onData = bind(onRetrieval, _1, _2, req);
    m_face->expressInterest(req->m_interest, onData,
                            [&](const Interest& interest, const lp::Nack&) {
                              onFailure(interest, req);
                            },
                            bind(&KeyManager::onTimeout, this, _1, req->m_nRetries, req,
                                 onRetrieval, onFailure));
  }
}

void
KeyManager::loadAnchor(shared_ptr<const Data> cert, const std::string& groupId)
{
  if (cert == nullptr)
    throw std::invalid_argument("Certificate should not be empty.");

  m_anchorCache.insert(cert, groupId);
}

void
KeyManager::loadAnchor(const std::string& groupId, const std::string& certfilePath,
                       const time::nanoseconds& refreshPeriod, bool isDir)
{
  m_anchorCache.insert(groupId, certfilePath, refreshPeriod, isDir);
}

void
KeyManager::loadVerifiedKey(shared_ptr<const Data> cert,
                            const time::system_clock::TimePoint& expireTime)
{
  if (cert == nullptr)
    throw std::invalid_argument("Certificate should not be empty.");

  m_verifiedKeyCache.insert(cert, expireTime);
}

void
KeyManager::loadUnverifiedKey(shared_ptr<const Data> cert)
{
  if (cert == nullptr)
    throw std::invalid_argument("Certificate should not be empty.");

  m_unVerifiedKeyCache.insert(*cert);
}

void
KeyManager::onTimeout(const Interest& interest, int remainRetries,
                      shared_ptr<KeyRequest>& req, const RetrievalSuccessCallback& onRetrieval,
                      const RetrievalFailureCallback& onFailure)
{
  if (remainRetries > 0) {
    DataCallback onData = bind(onRetrieval, _1, _2, req);
    m_face->expressInterest(interest, onData,
                            [&](const Interest& interest, const lp::Nack&) { onFailure(interest, req); },
                            bind(&KeyManager::onTimeout, this, _1, remainRetries - 1, req,
                                 onRetrieval, onFailure));
  }
  else
    onFailure(interest, req);
}

} // namespace validator
} // namespace security
} // namespace ndn

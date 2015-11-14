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

#ifndef NDN_SECURITY_VALIDATOR_KEY_MANAGER_HPP
#define NDN_SECURITY_VALIDATOR_KEY_MANAGER_HPP

#include "key-request.hpp"
#include "certificate-cache.hpp"
#include "../detail/trust-anchor-container.hpp"
#include "../../util/in-memory-storage-persistent.hpp"

namespace ndn {
namespace security {
namespace validator {

typedef function<void(const Interest&, const Data&,
                      shared_ptr<KeyRequest>&)> RetrievalSuccessCallback;
typedef function<void(const Interest&, shared_ptr<KeyRequest>&)> RetrievalFailureCallback;


class KeyManager
{
public:
  /**
   * @brief creates a new key manager
   *
   * @param face Pointer to face in case key manager may need to retrieve certificates.
   *             Passing a null pointer implies the key manager is in offline mode.
   */
  explicit
  KeyManager(Face* face = nullptr);

  ~KeyManager();

  /**
   * @brief retrieve trusted certificate based on key request.
   *
   * The key manager would first try its trust anchor cache, then verified key cache.
   *
   * @param req   KeyRequest that contains the context of interest. 
   *
   * @return found certificate, nullptr if not found.
   */
  shared_ptr<const Data>
  retrieveTrustedCert(const Interest& interest);

  /**
   * @brief retrieve certificate based on key request.
   *
   * The key manager would first searched in its unverified key cache, if no
   * certificate is found, it will try to retrieve from network.
   *
   * @param req          KeyRequest that contains the context of interest. 
   * @param onRetrieval  callback invoked when a certificate is retrieved.
   * @param onFailure    callback invoked when no certificate is retrieved.
   */
  void
  retrieveCertificate(shared_ptr<KeyRequest>& req, const RetrievalSuccessCallback& onRetrieval,
                      const RetrievalFailureCallback& onFailure);

  /**
   * @brief fetch key from network based on key request.
   *
   * The key manager will send an interest using the interest name inside @p req.
   *
   * @param req the key request with interest and callbacks.
   * @param onRetrieval  callback invoked when a certificate is retrieved.
   * @param onFailure    callback invoked when no certificate is retrieved.
   */
  void
  fetchKeyFromNetwork(shared_ptr<KeyRequest>& req, const RetrievalSuccessCallback& onRetrival,
                      const RetrievalFailureCallback& onFailure);

  /**
   * @brief load static trust anchor
   *
   * @param cert     the certificate packet, must not be nullptr.
   * @param groupId  Certificate group id.
   *
   * @throw std::invalid_argument when cert is nullptr
   */
  void
  loadAnchor(shared_ptr<const Data> cert, const std::string& groupId = "");

  /**
   * @brief load dynamic trust anchors.
   *
   * @param groupId          Certificate group id, must not be empty.
   * @param certfilePath     Specifies the path to load the trust anchors.
   * @param refreshPeriod    Refresh period for the trust anchors, must be positive.
   *                         Relevant trust anchors will only be updated when find and
   *                         findByGroupId are called.
   * @param isDir            Tells whether the path is a directory or a single file.
   */
  void
  loadAnchor(const std::string& groupId, const std::string& certfilePath,
             const time::nanoseconds& refreshPeriod, bool isDir = false);

  /**
   * @brief load verified key.
   *
   * @param cert        the certificate packet, must not be nullptr.
   * @param expireTime  the expire time of the certificate.
   *
   * @throw std::invalid_argument when @p cert is nullptr
   */
  void
  loadVerifiedKey(shared_ptr<const Data> cert, const time::system_clock::TimePoint& expireTime);

  /**
   * @brief load unverified key.
   *
   * @param cert  the certificate packet, must not be nullptr.
   *
   * @throw std::invalid_argument when @p cert is nullptr
   */
  void
  loadUnverifiedKey(shared_ptr<const Data> cert);

  /**
   * @brief callback invoked when interest for fetching certificate times out.
   *
   * It will retry for @p remainRetries times and triggered @p onFailure if remainRetries is
   * no larger than 0.
   *
   * @param interest       The interest that times out.
   * @param remainRetries  The number of retries left.
   * @param req            KeyRequest that contains the context of interest. 
   * @param onRetrieval    callback when key is retrieved.
   * @param onFailure      Failure callback when there is no more retries remaining.
   */
  void
  onTimeout(const Interest& interest, int remainRetries,
            shared_ptr<KeyRequest>& req, const RetrievalSuccessCallback& onRetrieval,
            const RetrievalFailureCallback& onFailure);

  detail::TrustAnchorContainer&
  getMutableAnchorCache()
  {
    return m_anchorCache;
  }

private:
  /**
   * @brief preprocessing before retrieving key from network.
   * 
   * @param req   KeyRequest that contains the context of interest. 
   */
  virtual void
  preProcess(shared_ptr<KeyRequest>& req) = 0;

private:
  Face* m_face;
  CertificateCache m_verifiedKeyCache;
  detail::TrustAnchorContainer m_anchorCache;
  util::InMemoryStoragePersistent m_unVerifiedKeyCache;
};

} // namespace validator
} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_VALIDATOR_KEY_MANAGER_HPP

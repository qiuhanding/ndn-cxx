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

#ifndef NDN_SECURITY_SCHEMA_TRUST_ANCHOR_HPP
#define NDN_SECURITY_SCHEMA_TRUST_ANCHOR_HPP

#include "name-function.hpp"
#include "../identity-certificate.hpp"

namespace ndn {
namespace security {
class TrustAnchor : public NameFunction
{
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  TrustAnchor(const std::string& id, const std::string& regex, const std::string& certfilePath,
              bool shouldRefresh,
              const time::nanoseconds& refreshPeriod =
              time::duration_cast<time::nanoseconds>(time::seconds(0)));

  TrustAnchor(const std::string& id, const std::string& regex, const std::string& base64Str);

  ~TrustAnchor()
  {
  }

  const shared_ptr<IdentityCertificate>
  getCertificate()
  {
    return m_cert;
  }

  const Name&
  getKeyName() const
  {
    return m_keyName;
  }

  const time::system_clock::TimePoint&
  getLastRefresh() const
  {
    return m_lastRefresh;
  }

  const time::nanoseconds&
  getRefreshPeriod() const
  {
    return m_refreshPeriod;
  }

  void
  setLastRefresh(const time::system_clock::TimePoint& lastRefresh)
  {
    m_lastRefresh = lastRefresh;
  }

  void
  refresh();

private:
  shared_ptr<IdentityCertificate> m_cert;
  Name m_keyName;
  std::string m_path;
  bool m_shouldRefresh;
  time::nanoseconds m_refreshPeriod;
  time::system_clock::TimePoint m_lastRefresh;
};

typedef shared_ptr<TrustAnchor> TrustAnchorPtr;

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_SCHEMA_TRUST_ANCHOR_HPP


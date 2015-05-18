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

#include "trust-anchor.hpp"

#include "../../util/io.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace security {

TrustAnchor::TrustAnchor(const std::string& id, const std::string& regex, const std::string& certfilePath,
                         bool shouldRefresh,
                         const time::nanoseconds& refreshPeriod)
  : NameFunction(id, regex)
  , m_path(certfilePath)
  , m_shouldRefresh(shouldRefresh)
  , m_refreshPeriod(refreshPeriod)
{
  shared_ptr<IdentityCertificate> idCert =
    io::load<IdentityCertificate>(certfilePath);

  if (static_cast<bool>(idCert)) {
    BOOST_ASSERT(idCert->getName().size() >= 1);
    m_cert = idCert;
    m_keyName = idCert->getName().getPrefix(-1);
    if (m_shouldRefresh)
      m_lastRefresh = time::system_clock::now() - refreshPeriod;
    else
      m_lastRefresh = time::system_clock::TimePoint::max();
  }
  else
    throw Error("Cannot read certificate from file: " + certfilePath);
}

TrustAnchor::TrustAnchor(const std::string& id, const std::string& regex, const std::string& base64Str)
  : NameFunction(id, regex)
  , m_path("")
  , m_shouldRefresh(false)
  , m_refreshPeriod(time::duration_cast<time::nanoseconds>(time::seconds(0)))
  , m_lastRefresh(time::system_clock::TimePoint::max())
{
  std::stringstream ss(base64Str);
  shared_ptr<IdentityCertificate> idCert = io::load<IdentityCertificate>(ss);
  if (static_cast<bool>(idCert)) {
    BOOST_ASSERT(idCert->getName().size() >= 1);
    m_cert = idCert;
    m_keyName = idCert->getName().getPrefix(-1);
  }
  else
    throw Error("Cannot decode certificate from base64-string");
}

void
TrustAnchor::refresh()
{
  using namespace boost::filesystem;

  shared_ptr<IdentityCertificate> idCert =
    io::load<IdentityCertificate>(m_path);
  if (static_cast<bool>(idCert))
    m_cert = idCert;
}

} // namespace security
} // namespace ndn

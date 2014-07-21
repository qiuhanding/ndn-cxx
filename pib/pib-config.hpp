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

#ifndef NDN_PIB_PIB_CONFIG_HPP
#define NDN_PIB_PIB_CONFIG_HPP

#include "security/identity-certificate.hpp"

#include <string>
#include <boost/property_tree/ptree.hpp>


namespace ndn {
namespace pib {

typedef boost::property_tree::ptree ConfigSection;

class PibConfig : noncopyable
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  PibConfig();

  PibConfig(const std::string& input, const std::string& filename);

  ~PibConfig();

  void
  load(const std::string& filename);

  void
  load(const std::string& input, const std::string& filename);

  void
  load(std::istream& input, const std::string& filename);

  void
  load(const ConfigSection& configSection, const std::string& filename);

  const std::string&
  getDbDir() const
  {
    return m_dbDir;
  }

  const std::string&
  getTpmDir() const
  {
    return m_tpmDir;
  }

  const std::string&
  getPibRootCertPath() const
  {
    return m_pibRootCertPath;
  }

  const shared_ptr<IdentityCertificate>&
  getPibRootCert() const
  {
    return m_pibRootCert;
  }

private:
  std::string m_dbDir;
  std::string m_tpmDir;

  std::string m_pibRootCertPath;
  shared_ptr<IdentityCertificate> m_pibRootCert;
};

} // namespace pib
} // namespace ndn

#endif // NDN_PIB_PIB_CONFIG_HPP

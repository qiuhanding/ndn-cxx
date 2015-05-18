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

#ifndef NDN_SECURITY_SCHEMA_SIGNATURE_REQUIREMENT_H
#define NDN_SECURITY_SCHEMA_SIGNATURE_REQUIREMENT_H

#include <unordered_set>

#include "common.hpp"
#include "../../signature.hpp"

namespace ndn {
namespace security {

class SignatureRequirement
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

  explicit
  SignatureRequirement(const SchemaSection& schemaSection);

  ~SignatureRequirement()
  {
  }

  bool
  checkRsaKeySize(size_t length);

  bool
  check(const Signature& sig);

  const size_t&
  getKeySize()
  {
    return m_keySize;
  }

  const std::unordered_set<uint32_t>
  getSigningPolicies()
  {
    return m_signingPolicies;
  }

private:
  std::unordered_set<uint32_t> m_signingPolicies;
  size_t m_keySize;
};

} // namespace security
} // namespace ndn

#endif // NDN_SECURITY_SCHEMA_SIGNATURE_REQUIREMENT_H

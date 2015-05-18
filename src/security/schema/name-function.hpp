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

#ifndef NDN_SECURITY_SCHEMA_NAME_FUNCTION_H
#define NDN_SECURITY_SCHEMA_NAME_FUNCTION_H

#include "common.hpp"
#include "../../util/regex.hpp"
#include "../../common.hpp"
#include "../../util/regex.hpp"

namespace ndn {
namespace security {

class NameFunction
{
public:
  explicit
  NameFunction(const std::string& id, const std::string& regex)
    : m_id(id)
    , m_regex(regex)
  {
  }

  virtual
  ~NameFunction()
  {
  }

  bool
  checkName(const Name& packetName);

  std::string
  derivePattern(const std::vector<Name>& backRefs);

  const std::string&
  getId() const
  {
    return m_id;
  }

  const Regex&
  getRegex() const
  {
    return m_regex;
  }

  void
  getNameFromBackRefs(const std::vector<std::string>& backRefs, std::vector<Name>& res);

private:
  std::string m_id;
  Regex m_regex;
};

} // namesapce security
} // namespace ndn

#endif // NDN_SECURITY_SCHEMA_NAME_FUNCTION_H


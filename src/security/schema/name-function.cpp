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

#include "name-function.hpp"
#include <boost/algorithm/string.hpp>

namespace ndn {
namespace security {

bool
NameFunction::checkName(const Name& packetName)
{
  return m_regex.match(packetName);
}

std::string
NameFunction::derivePattern(const std::vector<Name>& backRefs)
{ // accept back references to derive pattern
  return m_regex.inferPattern(backRefs);
}

void
NameFunction::getNameFromBackRefs(const std::vector<std::string>& backRefs,
                                  std::vector<Name>& res)
{
  for (const auto& backref : backRefs) {
    if (boost::iequals(backref, "null"))
      res.push_back(Name());
    else {
      Name name;
      try {
        name = m_regex.expand(backref);
      }
      catch (RegexMatcher::Error) {
        name = Name(backref);
      }
      res.push_back(name);
    }
  }
}

} // namespace security
} // namespace ndn

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

#include "signer.hpp"

namespace ndn {
namespace security {

Signer::Signer(std::string signer)
{
  std::remove_if(signer.begin(),
                 signer.end(),
                 [](char x){return std::isspace(x);});
  size_t pos = signer.find('(');
  if (pos == std::string::npos)
    throw Error("Expect Back Reference List");
  m_id = signer.substr(0, pos);
  size_t end = signer.find(')');
  if (end - pos == 1)
    return;
  size_t start = pos + 1;
  pos = signer.find(',', start);
  while (start != std::string::npos) {
    std::string backref;
    if (pos == std::string::npos) {
      m_backrefs.push_back(signer.substr(start, signer.length()- start - 1));
      break;
    }
    else {
      m_backrefs.push_back(signer.substr(start, pos-start));
      start = pos + 1;
      pos = signer.find(',', start);
    }
  }
}

} // namespace security
} // namespace ndn

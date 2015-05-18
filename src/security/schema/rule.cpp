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

#include "rule.hpp"

namespace ndn {
namespace security {

Rule::Rule(const std::string& id, const std::string& regex, const std::string& signer)
  : NameFunction(id, regex)
{
  size_t split = signer.find('|');
  size_t start = 0;
  while (start != std::string::npos) {
    if (split == std::string::npos) {
      m_signers.push_back(make_shared<Signer>(signer.substr(start)));
      break;
    }
    else {
      m_signers.push_back(make_shared<Signer>(signer.substr(start, split-start)));
      start = split + 1;
      split = signer.find('|', start);
    }
  }
}

} // namespace security
} // namespace ndn

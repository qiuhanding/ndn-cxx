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

#include "regex-component-matcher.hpp"

namespace ndn {

RegexComponentMatcher::RegexComponentMatcher(const std::string& expr,
                                             shared_ptr<RegexBackrefManager> backrefManager,
                                             bool isExactMatch)
  : RegexMatcher(expr, EXPR_COMPONENT, backrefManager)
  , m_isExactMatch(isExactMatch)
{
  compile();
}

RegexComponentMatcher::~RegexComponentMatcher()
{
}

bool
RegexComponentMatcher::match(const Name& name, size_t offset, size_t len)
{
  m_matchResult.clear();

  if (m_expr.empty()) {
    m_matchResult.push_back(name.get(offset));
    return true;
  }

  if (m_isExactMatch) {
    std::string targetStr = name.get(offset).toUri();
    if (targetStr == m_expr) {
      m_matchResult.push_back(name.get(offset));
      return true;
    }
  }
  else {
    throw Error("Non-exact component search is not supported yet!");
  }

  return false;
}

void
RegexComponentMatcher::derivePattern(std::string& pattern)
{
  if (m_matchResult.size() == 0)
    pattern += "<" + m_expr + ">";
  else {
    pattern += "<";
    for (const auto& result : m_matchResult) {
      pattern += result.toUri();
    }
    pattern += ">";
  }
}

void
RegexComponentMatcher::compile()
{
}

} // namespace ndn

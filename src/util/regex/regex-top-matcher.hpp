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

#ifndef NDN_UTIL_REGEX_REGEX_TOP_MATCHER_HPP
#define NDN_UTIL_REGEX_REGEX_TOP_MATCHER_HPP

#include "../../common.hpp"

#include "regex-matcher.hpp"

namespace ndn {

class RegexPatternListMatcher;
class RegexBackrefManager;

class RegexTopMatcher: public RegexMatcher
{
public:
  RegexTopMatcher(const std::string& expr, const std::string& expand = "");

  virtual
  ~RegexTopMatcher() NDN_CXX_DECL_FINAL;

  bool
  match(const Name& name);

  virtual bool
  match(const Name& name, size_t offset, size_t len) NDN_CXX_DECL_FINAL;

  virtual Name
  expand(const std::string& expand = "");

  virtual void
  derivePattern(std::string& pattern) NDN_CXX_DECL_FINAL;

  virtual void
  clearMatchResult() NDN_CXX_DECL_FINAL;

  static shared_ptr<RegexTopMatcher>
  fromName(const Name& name);

  std::string
  inferPattern(const std::vector<Name>& backRefs);

protected:
  virtual void
  compile() NDN_CXX_DECL_FINAL;

private:
  std::string
  getItemFromExpand(const std::string& expand, size_t& offset);

  static std::string
  convertSpecialChar(const std::string& str);

private:
  const std::string m_expand;
  shared_ptr<RegexPatternListMatcher> m_matcher;
  shared_ptr<RegexBackrefManager> m_backrefManager;
};

} // namespace ndn

#endif // NDN_UTIL_REGEX_REGEX_TOP_MATCHER_HPP

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

#ifndef NDN_UTIL_REGEX_REGEX_PATTERN_LIST_MATCHER_HPP
#define NDN_UTIL_REGEX_REGEX_PATTERN_LIST_MATCHER_HPP

#include "../../common.hpp"

#include "regex-matcher.hpp"

namespace ndn {

class RegexBackrefManager;

class RegexPatternListMatcher : public RegexMatcher
{
public:
  RegexPatternListMatcher(const std::string& expr, shared_ptr<RegexBackrefManager> backrefManager);

  virtual
  ~RegexPatternListMatcher() NDN_CXX_DECL_FINAL;

  virtual void
  derivePattern(std::string& pattern) NDN_CXX_DECL_FINAL;

  virtual void
  clearMatchResult() NDN_CXX_DECL_FINAL;

protected:
  virtual void
  compile() NDN_CXX_DECL_FINAL;

private:
  bool
  extractPattern(size_t index, size_t* next);

  int
  extractSubPattern(const char left, const char right, size_t index);

  int
  extractRepetition(size_t index);

private:

};

} // namespace ndn

#endif // NDN_UTIL_REGEX_REGEX_PATTERN_LIST_MATCHER_HPP

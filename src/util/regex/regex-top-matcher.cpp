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

#include "regex-top-matcher.hpp"

#include "regex-backref-manager.hpp"
#include "regex-pattern-list-matcher.hpp"
#include "regex-backref-matcher.hpp"

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

namespace ndn {

RegexTopMatcher::RegexTopMatcher(const std::string& expr, const std::string& expand)
  : RegexMatcher(expr, EXPR_TOP)
  , m_expand(expand)
{
  m_backrefManager = make_shared<RegexBackrefManager>();
  compile();
}

RegexTopMatcher::~RegexTopMatcher()
{
}

void
RegexTopMatcher::compile()
{
  std::string expr = m_expr;

  // On OSX 10.9, boost, and C++03 the following doesn't work without ndn::
  // because the argument-dependent lookup prefers STL to boost
  m_matcher = ndn::make_shared<RegexPatternListMatcher>(expr,
                                                        m_backrefManager);
}

bool
RegexTopMatcher::match(const Name& name)
{
  m_matchResult.clear();

  if (m_matcher->match(name, 0, name.size())) {
    m_matchResult = m_matcher->getMatchResult();
    return true;
  }
  else
    return false;
}

bool
RegexTopMatcher::match(const Name& name, size_t, size_t)
{
  return match(name);
}

Name
RegexTopMatcher::expand(const std::string& expandStr)
{
  Name result;

  size_t backrefNo = m_backrefManager->size();

  std::string expand;

  if (!expandStr.empty())
    expand = expandStr;
  else
    expand = m_expand;

  size_t offset = 0;
  while (offset < expand.size()) {
    std::string item = getItemFromExpand(expand, offset);
    if (item[0] == '<') {
      result.append(item.substr(1, item.size() - 2));
    }
    if (item[0] == '$') {
      size_t index = boost::lexical_cast<size_t>(item.substr(1, item.size() - 1));

      if (0 == index) {
        std::vector<name::Component>::iterator it = m_matchResult.begin();
        std::vector<name::Component>::iterator end = m_matchResult.end();
        for (; it != end; it++)
          result.append(*it);
      }
      else if (index <= backrefNo) {
        std::vector<name::Component>::const_iterator it =
          m_backrefManager->getBackref(index - 1)->getMatchResult().begin();
        std::vector<name::Component>::const_iterator end =
          m_backrefManager->getBackref(index - 1)->getMatchResult().end();
        for (; it != end; it++)
          result.append(*it);
      }
      else
        throw Error("Exceed the range of back reference");
    }
  }
  return result;
}

std::string
RegexTopMatcher::inferPattern(const std::vector<Name>& backRefs)
{
  if (backRefs.size() != m_backrefManager->size()) {
    throw Error("Number of names and sub groups does not equal");
  }

  clearMatchResult();

  size_t index = 0;
  for (const auto& name : backRefs) {
    auto backrefMatcher =
      static_pointer_cast<RegexBackrefMatcher>(m_backrefManager->getBackref(index));
    if (name.empty()) {
      index++;
      continue;
    }
    std::vector<name::Component> oldResult;
    oldResult = backrefMatcher->getMatchResult();
    bool res = backrefMatcher->match(name, 0, name.size());
    if (!res)
      throw Error("Name does not match pattern");

    std::vector<name::Component> newResult;
    newResult = backrefMatcher->getMatchResult();

    if (oldResult.size() != 0) {
      for (size_t i = 0; i < oldResult.size(); i++) {
        if (oldResult[i] != newResult[i])
          throw Error("There are inconsistency in the input!");
      }
    }
    index++;
  }

  std::string res = "";
  derivePattern(res);
  return res;

}

void
RegexTopMatcher::derivePattern(std::string& pattern)
{
  m_matcher->derivePattern(pattern);
}

void
RegexTopMatcher::clearMatchResult()
{
  m_matchResult.clear();
  m_matcher->clearMatchResult();
}

std::string
RegexTopMatcher::getItemFromExpand(const std::string& expand, size_t& offset)
{
  size_t begin = offset;

  if (expand[offset] == '$') {
    offset++;
    if (offset >= expand.size())
      throw Error("wrong format of expand string!");

    while (expand[offset] <= '9' and expand[offset] >= '0') {
      offset++;
      if (offset > expand.size())
        throw Error("wrong format of expand string!");
    }
    if (offset > begin + 1)
      return expand.substr(begin, offset - begin);
    else
      throw Error("wrong format of expand string!");
  }
  else if (expand[offset] == '<') {
    offset++;
    if (offset >= expand.size())
      throw Error("wrong format of expand string!");

    size_t left = 1;
    size_t right = 0;
    while (right < left) {
      if (expand[offset] == '<')
        left++;
      if (expand[offset] == '>')
        right++;
      offset++;
      if (offset >= expand.size())
        throw Error("wrong format of expand string!");
    }
    return expand.substr(begin, offset - begin);
  }
  else
    throw Error("wrong format of expand string!");
}

shared_ptr<RegexTopMatcher>
RegexTopMatcher::fromName(const Name& name)
{
  std::string regexStr("");

  for (const auto& comp : name) {
    regexStr.append("<");
    regexStr.append(convertSpecialChar(comp.toUri()));
    regexStr.append(">");
  }

  // On OSX 10.9, boost, and C++03 the following doesn't work without ndn::
  // because the argument-dependent lookup prefers STL to boost
  return ndn::make_shared<RegexTopMatcher>(regexStr);
}

std::string
RegexTopMatcher::convertSpecialChar(const std::string& str)
{
  std::string newStr;
  for (size_t i = 0; i < str.size(); i++) {
    char c = str[i];
    switch (c)
      {
      case '.':
      case '[':
      case '{':
      case '}':
      case '(':
      case ')':
      case '\\':
      case '*':
      case '+':
      case '?':
      case '|':
      case '^':
      case '$':
        newStr.push_back('\\');
        // Fallthrough
      default:
        newStr.push_back(c);
        break;
      }
  }

  return newStr;
}

} // namespace ndn

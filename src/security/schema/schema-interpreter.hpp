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

#ifndef NDN_SECURITY_SCHEMA_INTERPRETER_H
#define NDN_SECURITY_SCHEMA_INTERPRETER_H

#include "../../data.hpp"
#include "../../interest.hpp"
#include "signature-requirement.hpp"
#include "rule.hpp"
#include "common.hpp"
#include "trust-anchor-container.hpp"

namespace ndn {
namespace security {

namespace mi = boost::multi_index;

typedef mi::multi_index_container<
  RulePtr,
  mi::indexed_by<
    mi::sequenced<>,
    mi::hashed_unique<
      mi::const_mem_fun<NameFunction, const std::string&, &NameFunction::getId>
      >
    >
> DataRuleContainer;

typedef std::vector<shared_ptr<Rule> > RuleList;
typedef DataRuleContainer::nth_index<1>::type DataRuleContainerById;
typedef TrustAnchorContainer::nth_index<1>::type TrustAnchorContainerById;
typedef TrustAnchorContainer::nth_index<0>::type TrustAnchorContainerByName;
typedef DynamicTrustAnchorContainer::nth_index<2>::type DynamicTrustAnchorContainerByTime;
typedef DynamicTrustAnchorContainer::nth_index<1>::type DynamicTrustAnchorContainerById;
typedef DynamicTrustAnchorContainer::nth_index<0>::type DynamicTrustAnchorContainerByName;


class SchemaInterpreter
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

  SchemaInterpreter();

  ~SchemaInterpreter();

  void
  load(const std::string& input, const std::string& filename);

  void
  load(std::istream& input, const std::string& filename);

  void
  load(const SchemaSection& schemaSection,
       const std::string& filename);

  void
  reset();

  bool
  checkSignature(const Signature& signature);

  bool
  checkDataRule(const Name& dataName, const Name& keyLocator);

  bool
  checkInterestRule(const Name& interestName, const Name& keyLocator);

  bool
  isEmpty();

  bool
  getCheckFlag();

  const DataRuleContainer&
  getDataRules();

  const RuleList&
  getInterestRules();

  const TrustAnchorContainer&
  getStaticTrustAnchors();

  const DynamicTrustAnchorContainer&
  getDynamicTrustAnchors();

  shared_ptr<const SignatureRequirement>
  getSigReq();

  void
  refreshAnchors();

  shared_ptr<const Certificate>
  getCertificate(const Name& keyLocatorName);

  shared_ptr<const Certificate>
  getCertificate(const std::string& ruleId);

  std::vector<std::pair<std::string, std::string> >
  deriveSignerPatternFromName(const Name& name);

  std::vector<std::pair<std::string, std::string> >
  derivePatternFromRuleId(const std::string& ruleId);

private:
  void
  onConfigRule(const SchemaSection& schemaSection, bool isForData);

  void
  onConfigTrustAnchor(const SchemaSection& schemaSection,
                      const std::string& filename);

  time::nanoseconds
  getRefreshPeriod(std::string refreshString);

  time::nanoseconds
  getDefaultRefreshPeriod();

private:
  RuleList m_interestRules;
  DataRuleContainer m_dataRules;
  TrustAnchorContainer m_staticAnchors;
  DynamicTrustAnchorContainer m_dynamicAnchors;
  shared_ptr<SignatureRequirement> m_sigReq;
  bool m_checkFlag;
};

inline bool
SchemaInterpreter::getCheckFlag()
{
  return m_checkFlag;
}

inline const DataRuleContainer&
SchemaInterpreter::getDataRules()
{
  return m_dataRules;
}

inline const RuleList&
SchemaInterpreter::getInterestRules()
{
  return m_interestRules;
}

inline const TrustAnchorContainer&
SchemaInterpreter::getStaticTrustAnchors()
{
  return m_staticAnchors;
}

inline const DynamicTrustAnchorContainer&
SchemaInterpreter::getDynamicTrustAnchors()
{
  return m_dynamicAnchors;
}

inline shared_ptr<const SignatureRequirement>
SchemaInterpreter::getSigReq()
{
  return m_sigReq;
}

} // namespace security
} // namespace ndn
#endif // NDN_SECURITY_SCHEMA_INTERPRETER_H

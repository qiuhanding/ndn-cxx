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

#include "schema-interpreter.hpp"

#include <boost/filesystem.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace security {

SchemaInterpreter::SchemaInterpreter()
  :m_checkFlag(true)
{
}

SchemaInterpreter::~SchemaInterpreter()
{
}

void
SchemaInterpreter::load(const std::string& input, const std::string& filename)
{
  std::istringstream inputStream(input);
  load(inputStream, filename);
}

void
SchemaInterpreter::load(std::istream& input, const std::string& filename){
  SchemaSection tree;
  try {
      boost::property_tree::read_info(input, tree);
  }
  catch (boost::property_tree::info_parser_error& error) {
    std::stringstream msg;
    msg << "Failed to parse configuration file";
    msg << " " << filename;
    msg << " " << error.message() << " line " << error.line();
    throw Error(msg.str());
  }

  load(tree, filename);
}

void
SchemaInterpreter::load(const SchemaSection& schemaSection,
                       const std::string& filename)
{
  BOOST_ASSERT(!filename.empty());

  reset();

  if (schemaSection.begin() == schemaSection.end()) {
    std::string msg = "Error processing configuration file";
    msg += ": ";
    msg += filename;
    msg += " no data";
    throw Error(msg);
  }

  for (const auto sec : schemaSection) {
    const std::string& sectionName = sec.first;
    const SchemaSection& section = sec.second;

    if (boost::iequals(sectionName, "any")) {
      const std::string& flag = section.data();
      if (boost::iequals(flag, "true")) {
        m_checkFlag = false;
        return;
      }
      continue;
    }
    else if (boost::iequals(sectionName, "rule")) {
      onConfigRule(section, true);
    }
    else if (boost::iequals(sectionName, "interest-rule")) {
      onConfigRule(section, false);
    }
    else if (boost::iequals(sectionName, "anchor")) {
      onConfigTrustAnchor(section, filename);
    }
    else if (boost::iequals(sectionName, "sig-req")) {
      m_sigReq = make_shared<SignatureRequirement>(section);
    }
    else {
      std::string msg = "Error processing configuration file";
      msg += " ";
      msg += filename;
      msg += " unrecognized section: " + sectionName;
      throw Error(msg);
    }
  }
}

void
SchemaInterpreter::reset()
{
  m_interestRules.clear();
  m_dataRules.clear();
  m_staticAnchors.clear();
  m_dynamicAnchors.clear();
  m_checkFlag = true;
}

bool
SchemaInterpreter::checkSignature(const Signature& signature)
{
  return (!m_checkFlag) || m_sigReq->check(signature);
}

bool
SchemaInterpreter::checkDataRule(const Name& dataName, const Name& keyLocator)
{
  if (!m_checkFlag)
    return true;

  for (const auto& rule : m_dataRules.get<0>()) {
    BOOST_ASSERT(rule != 0);
    if (!rule->checkName(dataName))
      continue;

    std::vector<shared_ptr<Signer>> signers = rule->getSigners();
    for (const auto& signer : signers) {
      DataRuleContainerById::const_iterator dataItr = m_dataRules.get<1>().find(signer->getId());
      if (dataItr == m_dataRules.get<1>().end()) {
        TrustAnchorContainerById::const_iterator anchorItr =
          m_staticAnchors.get<1>().find(signer->getId());
        if (anchorItr != m_staticAnchors.get<1>().end()) {
          std::vector<Name> names;
          rule->getNameFromBackRefs(signer->getBackRefs(), names);
          Regex regex = Regex((*anchorItr)->derivePattern(names));
          if (regex.match(keyLocator))
            return true;
        }
        else {
          DynamicTrustAnchorContainerById::const_iterator dynamicAnchorItr =
            m_dynamicAnchors.get<1>().find(signer->getId());
          if (dynamicAnchorItr != m_dynamicAnchors.get<1>().end()) {
            std::vector<Name> names;
            rule->getNameFromBackRefs(signer->getBackRefs(), names);
            Regex regex = Regex((*dynamicAnchorItr)->derivePattern(names));
            if (regex.match(keyLocator))
              return true;
          }
        }
      }
      else {
        std::vector<Name> names;
        rule->getNameFromBackRefs(signer->getBackRefs(), names);
        Regex regex = Regex((*dataItr)->derivePattern(names));
        if (regex.match(keyLocator))
          return true;
      }
    }
  }
  return false;
}

bool
SchemaInterpreter::checkInterestRule(const Name& interestName, const Name& keyLocator)
{
  for (const auto& rule : m_interestRules) {
    BOOST_ASSERT(rule != 0);
    if (!rule->checkName(interestName))
      continue;

    std::vector<shared_ptr<Signer>> signers = rule->getSigners();
    for (const auto& signer : signers) {
      DataRuleContainerById::const_iterator dataItr = m_dataRules.get<1>().find(signer->getId());
      if (dataItr == m_dataRules.get<1>().end()) {
        TrustAnchorContainerById::const_iterator anchorItr =
          m_staticAnchors.get<1>().find(signer->getId());
        if (anchorItr != m_staticAnchors.get<1>().end()) {
          std::vector<Name> names;
          rule->getNameFromBackRefs(signer->getBackRefs(), names);
          Regex regex = Regex((*anchorItr)->derivePattern(names));
          if (regex.match(keyLocator))
            return true;
        }
        else {
          DynamicTrustAnchorContainerById::const_iterator dynamicAnchorItr =
            m_dynamicAnchors.get<1>().find(signer->getId());
          if (dynamicAnchorItr != m_dynamicAnchors.get<1>().end()) {
            std::vector<Name> names;
            rule->getNameFromBackRefs(signer->getBackRefs(), names);
            Regex regex = Regex((*dynamicAnchorItr)->derivePattern(names));
            if (regex.match(keyLocator))
              return true;
          }
        }
      }
      else {
        std::vector<Name> names;
        rule->getNameFromBackRefs(signer->getBackRefs(), names);
        Regex regex = Regex((*dataItr)->derivePattern(names));
        if (regex.match(keyLocator))
          return true;
      }
    }
  }
  return false;
}

bool
SchemaInterpreter::isEmpty()
{
  return (m_interestRules.empty() && m_dataRules.empty() &&
          m_staticAnchors.empty() && m_dynamicAnchors.empty());
}

void
SchemaInterpreter::refreshAnchors()
{
  time::system_clock::TimePoint now = time::system_clock::now();

  DynamicTrustAnchorContainerByTime::iterator cIt = m_dynamicAnchors.get<2>().begin();
  while (cIt != m_dynamicAnchors.get<2>().end() &&
         (*cIt)->getLastRefresh() + (*cIt)->getRefreshPeriod() < now) {
    shared_ptr<TrustAnchor>ptr = (*cIt);
    m_dynamicAnchors.get<2>().erase(cIt);
    ptr->refresh();
    ptr->setLastRefresh(now);
    m_dynamicAnchors.insert(ptr);
    cIt = m_dynamicAnchors.get<2>().begin();
  }
}

shared_ptr<const Certificate>
SchemaInterpreter::getCertificate(const Name& keyLocatorName)
{
  TrustAnchorContainerByName::const_iterator itr = m_staticAnchors.get<0>().find(keyLocatorName);
  if (itr != m_staticAnchors.get<0>().end()) {
    return (*itr)->getCertificate();
  }
  DynamicTrustAnchorContainerByName::const_iterator dItr = m_dynamicAnchors.get<0>().find(keyLocatorName);
  if (dItr != m_dynamicAnchors.get<0>().end()) {
    return (*dItr)->getCertificate();
  }
  return nullptr;
}

shared_ptr<const Certificate>
SchemaInterpreter::getCertificate(const std::string& ruleId)
{
  TrustAnchorContainerById::const_iterator itr = m_staticAnchors.get<1>().find(ruleId);
  if (itr != m_staticAnchors.get<1>().end()) {
    return (*itr)->getCertificate();
  }
  DynamicTrustAnchorContainerById::const_iterator dItr = m_dynamicAnchors.get<1>().find(ruleId);
  if (dItr != m_dynamicAnchors.get<1>().end()) {
    return (*dItr)->getCertificate();
  }
  return nullptr;
}

std::vector<std::pair<std::string, std::string> >
SchemaInterpreter::deriveSignerPatternFromName(const Name& name)
{
  std::vector<std::pair<std::string, std::string> > signerPatterns;
  RulePtr matchedRule;
  for (const auto& rule : m_dataRules.get<0>()) {
    BOOST_ASSERT(rule != 0);
    if (rule->checkName(name)) {
      matchedRule = rule;
      break;
    }
  }
  if (!static_cast<bool>(matchedRule)) {
    for (const auto& rule : m_interestRules) {
      BOOST_ASSERT(rule != 0);
      if (rule->checkName(name)) {
        matchedRule = rule;
        break;
      }
    }
  }

  if (!static_cast<bool>(matchedRule))
    return signerPatterns;

  std::vector<shared_ptr<Signer>> signers = matchedRule->getSigners();
  for (const auto& signer : signers) {
    DataRuleContainerById::const_iterator dataItr = m_dataRules.get<1>().find(signer->getId());
    if (dataItr == m_dataRules.get<1>().end()) {
      TrustAnchorContainerById::const_iterator anchorItr =
        m_staticAnchors.get<1>().find(signer->getId());
      if (anchorItr != m_staticAnchors.get<1>().end()) {
        std::vector<Name> names;
        matchedRule->getNameFromBackRefs(signer->getBackRefs(), names);
        signerPatterns.push_back(std::make_pair(signer->getId(),
                                                (*anchorItr)->derivePattern(names)));
      }
      else {
        DynamicTrustAnchorContainerById::const_iterator dynamicAnchorItr =
          m_dynamicAnchors.get<1>().find(signer->getId());
        if (dynamicAnchorItr != m_dynamicAnchors.get<1>().end()) {
          std::vector<Name> names;
          matchedRule->getNameFromBackRefs(signer->getBackRefs(), names);
          signerPatterns.push_back(std::make_pair(signer->getId(),
                                                  (*dynamicAnchorItr)->derivePattern(names)));
        }
      }
    }
    else {
      std::vector<Name> names;
      matchedRule->getNameFromBackRefs(signer->getBackRefs(), names);
      signerPatterns.push_back(std::make_pair(signer->getId(),
                                              (*dataItr)->derivePattern(names)));
    }
  }
  return signerPatterns;
}

std::vector<std::pair<std::string, std::string> >
SchemaInterpreter::derivePatternFromRuleId(const std::string& ruleId)
{
  std::vector<std::pair<std::string, std::string> > signerPatterns;
  DataRuleContainerById::const_iterator ruleItr = m_dataRules.get<1>().find(ruleId);
  if (ruleItr == m_dataRules.get<1>().end())
    return signerPatterns;

  std::vector<shared_ptr<Signer>> signers = (*ruleItr)->getSigners();
  for (const auto& signer : signers) {
    DataRuleContainerById::const_iterator dataItr = m_dataRules.get<1>().find(signer->getId());
    if (dataItr == m_dataRules.get<1>().end()) {
      TrustAnchorContainerById::const_iterator anchorItr =
        m_staticAnchors.get<1>().find(signer->getId());
      if (anchorItr != m_staticAnchors.get<1>().end()) {
        std::vector<Name> names;
        (*ruleItr)->getNameFromBackRefs(signer->getBackRefs(), names);
        signerPatterns.push_back(std::make_pair(signer->getId(),
                                                (*anchorItr)->derivePattern(names)));
      }
      else {
        DynamicTrustAnchorContainerById::const_iterator dynamicAnchorItr =
          m_dynamicAnchors.get<1>().find(signer->getId());
        if (dynamicAnchorItr != m_dynamicAnchors.get<1>().end()) {
          std::vector<Name> names;
          (*ruleItr)->getNameFromBackRefs(signer->getBackRefs(), names);
          signerPatterns.push_back(std::make_pair(signer->getId(),
                                                  (*dynamicAnchorItr)->derivePattern(names)));
        }
      }
    }
    else {
      std::vector<Name> names;
      (*ruleItr)->getNameFromBackRefs(signer->getBackRefs(), names);
      signerPatterns.push_back(std::make_pair(signer->getId(),
                                              (*dataItr)->derivePattern(names)));
    }
  }
  return signerPatterns;
}


// private:
void
SchemaInterpreter::onConfigRule(const SchemaSection& schemaSection, bool isForData)
{
  SchemaSection::const_iterator propertyIt = schemaSection.begin();

  // Get rule.id
  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first, "id"))
    throw Error("Expect <rule.id>!");

  std::string ruleId = propertyIt->second.data();
  propertyIt++;

  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first,"name"))
    throw Error("Expect <rule.name> in rule: " + ruleId + "!");

  // Get rule.name
  std::string name = propertyIt->second.data();
  propertyIt++;

  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first,"signer"))
    throw Error("Expect <rule.signer> in rule: " + ruleId + "!");
  // Get rule.signer
  std::string signer = propertyIt->second.data();
  propertyIt++;

  // Check other stuff
  if (propertyIt != schemaSection.end())
    throw Error("Expect the end of rule: " + ruleId);

  if (isForData) {
    m_dataRules.get<1>().insert(make_shared<Rule>(ruleId, name, signer));
  }
  else {
    m_interestRules.push_back(make_shared<Rule>(ruleId, name, signer));
  }
}

void
SchemaInterpreter::onConfigTrustAnchor(const SchemaSection& schemaSection,
                                       const std::string& filename)
{
  using namespace boost::filesystem;

  SchemaSection::const_iterator propertyIt = schemaSection.begin();

  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first, "id"))
    throw Error("Expect <trust-anchor.id>!");

  std::string anchorId = propertyIt->second.data();
  propertyIt++;

  // Get trust-anchor.type
  if (propertyIt == schemaSection.end() || !boost::iequals(propertyIt->first, "name"))
    throw Error("Expect <trust-anchor.name>!");

  std::string name = propertyIt->second.data();
  propertyIt++;

  if (propertyIt == schemaSection.end())
    throw Error("Expect more properties!");

  std::string type = propertyIt->first.data();

  if (boost::iequals(type, "file")) {
      // Get trust-anchor.file
      std::string file = propertyIt->second.data();
      propertyIt++;

      path certfilePath = absolute(file, path(filename).parent_path());

      if (propertyIt != schemaSection.end()) {
        if (boost::iequals(propertyIt->first, "refresh")) {
          time::nanoseconds refresh = getRefreshPeriod(propertyIt->second.data());
          propertyIt++;

          if (propertyIt != schemaSection.end())
            throw Error("Expect the end of trust-anchor!");

          m_dynamicAnchors.insert(make_shared<TrustAnchor>(anchorId, name,
                                                           certfilePath.string(),
                                                           true, refresh));
        }
        else
          throw Error("Expect <trust-anchor.refresh>!");
      }
      else {
        m_staticAnchors.insert(make_shared<TrustAnchor>(anchorId, name, certfilePath.string(), false));
      }
      return;
  }
  else if (boost::iequals(type, "base64")) {
    m_staticAnchors.insert(make_shared<TrustAnchor>(anchorId, name, propertyIt->second.data()));
    propertyIt++;

    // Check other stuff
    if (propertyIt != schemaSection.end())
      throw Error("Expect the end of trust-anchor!");

    return;
  }
  else
    throw Error("Unsupported trust-anchor.type: " + type);
}

time::nanoseconds
SchemaInterpreter::getRefreshPeriod(std::string inputString)
{
  char unit = inputString[inputString.size() - 1];
  std::string refreshString = inputString.substr(0, inputString.size() - 1);

  uint32_t number;

  try
    {
      number = boost::lexical_cast<uint32_t>(refreshString);
    }
  catch (boost::bad_lexical_cast&)
    {
      throw Error("Bad number: " + refreshString);
    }

  if (number == 0)
    return getDefaultRefreshPeriod();

  switch (unit)
    {
    case 'h':
      return time::duration_cast<time::nanoseconds>(time::hours(number));
    case 'm':
      return time::duration_cast<time::nanoseconds>(time::minutes(number));
    case 's':
      return time::duration_cast<time::nanoseconds>(time::seconds(number));
    default:
      throw Error(std::string("Wrong time unit: ") + unit);
    }
}

time::nanoseconds
SchemaInterpreter::getDefaultRefreshPeriod()
{
  return time::duration_cast<time::nanoseconds>(time::seconds(3600));
}

} // namespace security
} // namespace ndn

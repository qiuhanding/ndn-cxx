/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2014 Regents of the University of California.
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

#include "pib-config.hpp"

#include "util/io.hpp"

#include <boost/filesystem.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string.hpp>

namespace ndn {
namespace pib {

PibConfig::PibConfig()
{
}

PibConfig::PibConfig(const std::string& input, const std::string& filename)
{
  std::istringstream inputStream(input);
  load(inputStream, filename);
}

PibConfig::~PibConfig()
{
}

void
PibConfig::load(const std::string& filename)
{
  std::ifstream inputFile;
  inputFile.open(filename.c_str());
  if (!inputFile.good() || !inputFile.is_open())
    {
      std::string msg = "Failed to read configuration file: ";
      msg += filename;
      throw Error(msg);
    }
  load(inputFile, filename);
  inputFile.close();
}

void
PibConfig::load(const std::string& input, const std::string& filename)
{
  std::istringstream inputStream(input);
  load(inputStream, filename);
}


void
PibConfig::load(std::istream& input, const std::string& filename)
{
  ConfigSection tree;
  try
    {
      boost::property_tree::read_ini(input, tree);
    }
  catch (boost::property_tree::ini_parser_error& error)
    {
      std::stringstream msg;
      msg << "Failed to parse configuration file";
      msg << " " << filename;
      msg << " " << error.message() << " line " << error.line();
      throw Error(msg.str());
    }

  load(tree, filename);
}

void
PibConfig::load(const ConfigSection& configSection, const std::string& filename)
{
  using namespace boost::filesystem;

  BOOST_ASSERT(!filename.empty());

  // Get pib-dir
  try {
    m_dbDir = configSection.get<std::string>("pib-dir");
  }
  catch (boost::property_tree::ptree_bad_path& error) {
    throw Error("pib-dir is not specified");
  }

  // Get tpm-dir
  try {
    m_tpmDir = configSection.get<std::string>("tpm-dir");
  }
  catch (boost::property_tree::ptree_bad_path& error) {
    throw Error("tpm-dir is not specified");
  }

  // Get pib-root
  std::string rootFile;
  try {
    rootFile = configSection.get<std::string>("pib-root");
  }
  catch (boost::property_tree::ptree_bad_path& error) {
    throw Error("pib-root is not specified");
  }

  path certfilePath = absolute(rootFile, path(filename).parent_path());
  m_pibRootCertPath = certfilePath.string();
  m_pibRootCert = io::load<IdentityCertificate>(m_pibRootCertPath);
}

} // namespace pib
} // namespace ndn

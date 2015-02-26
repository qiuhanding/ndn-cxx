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

#include "pib/pib-config.hpp"
#include <boost/filesystem.hpp>

#include "boost-test.hpp"

namespace ndn {
namespace pib {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestPibConfig)

BOOST_AUTO_TEST_CASE(Basic)
{
  std::string CONFIG =
    "pib-dir=/tmp/pib\n"
    "tpm-dir=/tmp/pib/tpm\n"
    "pib-root=/tmp/pib/root.cert\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-pib.conf"));

  PibConfig pibConfig;
  pibConfig.load(CONFIG, CONFIG_PATH.native());

  BOOST_CHECK_EQUAL(pibConfig.getDbDir(), "/tmp/pib");
  BOOST_CHECK_EQUAL(pibConfig.getTpmDir(), "/tmp/pib/tpm");
  BOOST_CHECK_EQUAL(pibConfig.getPibRootCertPath(), "/tmp/pib/root.cert");
  BOOST_CHECK_EQUAL(static_cast<bool>(pibConfig.getPibRootCert()), false);
}

BOOST_AUTO_TEST_CASE(Basic2)
{
  std::string CONFIG =
    "tpm-dir=/tmp/pib/tpm\n"
    "pib-dir=/tmp/pib\n"
    "pib-root=/tmp/pib/root.cert\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-pib.conf"));

  PibConfig pibConfig;
  pibConfig.load(CONFIG, CONFIG_PATH.native());

  BOOST_CHECK_EQUAL(pibConfig.getDbDir(), "/tmp/pib");
  BOOST_CHECK_EQUAL(pibConfig.getTpmDir(), "/tmp/pib/tpm");
  BOOST_CHECK_EQUAL(pibConfig.getPibRootCertPath(), "/tmp/pib/root.cert");
  BOOST_CHECK_EQUAL(static_cast<bool>(pibConfig.getPibRootCert()), false);
}

BOOST_AUTO_TEST_CASE(MissingError)
{
  std::string CONFIG =
    "tpm-dir=/tmp/pib/tpm\n"
    "pib-root=/tmp/pib/root.cert\n";

  const boost::filesystem::path CONFIG_PATH =
    (boost::filesystem::current_path() / std::string("unit-test-pib.conf"));

  PibConfig pibConfig;
  BOOST_CHECK_THROW(pibConfig.load(CONFIG, CONFIG_PATH.native()), PibConfig::Error);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace pib
} // namespace ndn

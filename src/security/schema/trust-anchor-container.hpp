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

#ifndef NDN_SECURITY_TRUST_ANCHOR_CONTAINER_HPP
#define NDN_SECURITY_TRUST_ANCHOR_CONTAINER_HPP

#include "trust-anchor.hpp"

#include "../../util/crypto.hpp"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/mem_fun.hpp>



namespace ndn {
namespace security {

namespace mi = boost::multi_index;

struct NameHash
{
  std::size_t
  operator()(const Name& prefix) const
  {
    ndn::ConstBufferPtr buffer =
      ndn::crypto::sha256(prefix.wireEncode().wire(), prefix.wireEncode().size());

    BOOST_ASSERT(buffer->size() > sizeof(std::size_t));

    return *reinterpret_cast<const std::size_t*>(buffer->buf());
  }
};

struct NameEqual
{
  bool
  operator()(const Name& prefix1, const Name& prefix2) const
  {
    return prefix1 == prefix2;
  }
};

struct TrustAnchorContainer : public mi::multi_index_container<
  TrustAnchorPtr,
  mi::indexed_by<
    mi::hashed_unique<
      mi::const_mem_fun<TrustAnchor, const Name&, &TrustAnchor::getKeyName>,
      NameHash,
      NameEqual
      >,

    mi::hashed_unique<
      mi::const_mem_fun<NameFunction, const std::string&, &NameFunction::getId>
      >
    >
  >
{
};

struct DynamicTrustAnchorContainer : public mi::multi_index_container<
  TrustAnchorPtr,
  mi::indexed_by<
    mi::hashed_unique<
      mi::const_mem_fun<TrustAnchor, const Name&, &TrustAnchor::getKeyName>,
      NameHash,
      NameEqual
      >,

    mi::hashed_unique<
      mi::const_mem_fun<NameFunction, const std::string&, &NameFunction::getId>
      >,

    mi::ordered_unique<
      mi::const_mem_fun<TrustAnchor, const time::system_clock::TimePoint&,
                        &TrustAnchor::getLastRefresh>
      >
    >
  >
{
};

} // namspace security
} // namespace ndn

#endif // NDN_SECURITY_TRUST_ANCHOR_CONTAINER_HPP

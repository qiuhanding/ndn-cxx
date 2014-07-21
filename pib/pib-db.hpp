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

#ifndef NDN_PIB_PIB_DB_HPP
#define NDN_PIB_PIB_DB_HPP

#include "common.hpp"
#include "security/identity-certificate.hpp"
#include "util/event-emitter.hpp"

#include <set>
#include <vector>

struct sqlite3;

namespace ndn {
namespace pib {

/// @brief Callback to report changes on user info.
typedef function<void(const std::string&)> UserChangedEventHandler;

/// @brief Callback to report that a key is deleted.
typedef function<void(const std::string&, const Name&,
                      const name::Component&)> KeyDeletedEventHandler;

/**
 * @brief PibDb is a class to manage the database of PIB service.
 *
 * only public key related information is stored in this database.
 * Detail information can be found at:
 * http://redmine.named-data.net/projects/ndn-cxx/wiki/PublicKey_Info_Base
 */
class PibDb : noncopyable
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

  explicit
  PibDb(const std::string& dbDir = "");

public: // User management

  /**
   * @brief Update root certificate
   *
   * This method simply replaces the existing root user with the new one.
   * Access control (whether this method should be called) is determined
   * by PIB logic and validator.
   *
   * @throws Error if supplied certificate is wrong
   */
  void
  addRootUser(const IdentityCertificate& certificate);

  /**
   * @brief Update normal user certificate
   *
   * @throws Error if supplied certificate is wrong
   */
  void
  addUser(const IdentityCertificate& certificate);

  /// @brief Delete a user and its related tables
  void
  deleteUser(const std::string& userName);

  /// @brief Check if a user exists in PIB
  bool
  hasUser(const std::string& userName) const;

  /// @brief Get a user's management cert, return NULL if the user does not exist
  shared_ptr<IdentityCertificate>
  getUserMgmtCertificate(const std::string& userName) const;

  /// @brief Get all users
  void
  listUsers(std::set<std::string>& users) const;


public: // Identity management

  /// @brief Add an identity in a user's Identity table
  void
  addIdentity(const std::string& userName, const Name& identity);

  /// @brief Delete an identity in a user's Identity table
  void
  deleteIdentity(const std::string& userName, const Name& identity);

  /// @brief Check if an identity exists in a user's Identity table
  bool
  hasIdentity(const std::string& userName, const Name& identity) const;

  /// @brief Set the default identity of a user
  void
  setDefaultIdentityOfUser(const std::string& userName, const Name& identity);

  /**
   * @brief Get the default identity of a user
   *
   * @throws Error if no default identity exists
   */
  Name
  getDefaultIdentityOfUser(const std::string& userName) const;

  /// @brief Get all identities in a user's Identity table
  void
  listIdentitiesOfUser(const std::string& userName, std::vector<Name>& identities) const;


public: // Key management

  /// @brief Add key in a user's Key table
  void
  addKey(const std::string& userName,
         const Name& identity,
         const name::Component& keyId,
         const PublicKey& key);

  /**
   * @brief Get key from a user's Key table
   *
   * @return shared pointer to the key, empty pointer if the key does not exit
   */
  shared_ptr<PublicKey>
  getKey(const std::string& userName,
         const Name& identity,
         const name::Component& keyId) const;

  /// @brief Delete key from a user's Key table
  void
  deleteKey(const std::string& userName,
            const Name& identity,
            const name::Component& keyId);

  /// @brief Check if a key exists in a user's Key table
  bool
  hasKey(const std::string& userName,
         const Name& identity,
         const name::Component& keyId) const;

  /// @brief Set an identity's default key name
  void
  setDefaultKeyNameOfIdentity(const std::string& userName,
                              const Name& identity,
                              const name::Component& keyId);

  /**
   * @brief Get the default key name of an identity
   *
   * @throws Error if no default key is set for the identity
   */
  Name
  getDefaultKeyNameOfIdentity(const std::string& userName, const Name& identity) const;

  /// @brief Get all the key names of an identity in a user's key table
  void
  listKeyNamesOfIdentity(const std::string& userName,
                         const Name& identity, std::vector<Name>& keyNames) const;

public: // Certificate Management

  /// @brief Add a certificate in a user's cert table
  void
  addCertificate(const std::string& userName, const IdentityCertificate& certificate);

  /**
   * @brief Get a certificate from a user's cert table
   *
   * @return shared pointer to the certificate, empty pointer if the certificate does not exist
   */
  shared_ptr<IdentityCertificate>
  getCertificate(const std::string& userName, const Name& certificateName) const;

  /// @brief Delete a certificate from a user's cert table
  void
  deleteCertificate(const std::string& userName, const Name& certificateName);

  /// @brief Check if the certificate exist in a user's cert table
  bool
  hasCertificate(const std::string& userName, const Name& certificateName) const;

  /// @brief Set a key's default certificate name
  void
  setDefaultCertNameOfKey(const std::string& userName,
                          const Name& identity,
                          const name::Component& keyId,
                          const Name& certificateName);

  /**
   * @brief Get a key's default certificate name
   *
   * @throws Error if no default cert is set for the key
   */
  Name
  getDefaultCertNameOfKey(const std::string& userName,
                          const Name& identity,
                          const name::Component& keyId) const;

  /// @brief Get all the cert names of an key in a user's cert table
  void
  listCertNamesOfKey(const std::string& userName,
                     const Name& identity, const name::Component& keyId,
                     std::vector<Name>& certNames) const;

private:
  bool
  initializeTable(const std::string& tableName, const std::string& initCommand);

  void
  addUser(const std::string& userName, const IdentityCertificate& certificate);

public:
  util::EventEmitter<std::string> onUserChanged;
  util::EventEmitter<std::string, Name, name::Component> onKeyDeleted;

private:
  sqlite3* m_database;
};

} // namespace pib
} // namespace ndn


#endif // NDN_PIB_PIB_DB_HPP

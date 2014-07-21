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

#include "common.hpp"

#include "pib-db.hpp"
#include <sqlite3.h>
#include <boost/filesystem.hpp>

namespace ndn {
namespace pib {

using std::string;
using std::vector;
using std::set;

static const string ROOT("root");

static const string INIT_USER_TABLE =
  "CREATE TABLE IF NOT EXISTS                    "
  "  users(                                      "
  "      user                  BLOB NOT NULL,    "
  "      default_identity      BLOB,             "
  "      local_management_cert BLOB NOT NULL,    "
  "      PRIMARY KEY (user)                      "
  "  );                                          ";

static const string INIT_ID_TABLE =
  "CREATE TABLE IF NOT EXISTS                         "
  "  identities(                                      "
  "      user                 BLOB NOT NULL,          "
  "      identity             BLOB NOT NULL,          "
  "      default_key_id       BLOB,                   "
  "      PRIMARY KEY (user, identity)                 "
  "  );                                               ";

static const string INIT_KEY_TABLE =
  "CREATE TABLE IF NOT EXISTS                             "
  "  keys(                                                 "
  "      user                 BLOB NOT NULL,              "
  "      identity             BLOB NOT NULL,              "
  "      key_id               BLOB NOT NULL,              "
  "      key_type             INTEGER NOT NULL,           "
  "      key_bits             BLOB NOT NULL,              "
  "      default_cert_name    BLOB,                       "
  "      PRIMARY KEY (user, identity, key_id)             "
  "  );                                                   ";

static const string INIT_CERT_TABLE =
  "CREATE TABLE IF NOT EXISTS                                       "
  "  certificates(                                                   "
  "      user                 BLOB NOT NULL,                        "
  "      certificate_name     BLOB NOT NULL,                        "
  "      identity             BLOB NOT NULL,                        "
  "      key_id               BLOB NOT NULL,                        "
  "      certificate_data     BLOB NOT NULL,                        "
  "      PRIMARY KEY (user, certificate_name)                       "
  "  );                                                             ";

/**
 * A utility function to call the normal sqlite3_bind_text where the value and length are
 * value.c_str() and value.size().
 */
static int
sqlite3_bind_string(sqlite3_stmt* statement,
                    int index,
                    const string& value,
                    void(*destructor)(void*))
{
  return sqlite3_bind_text(statement, index, value.c_str(), value.size(), destructor);
}

/**
 * A utility function to call the normal sqlite3_bind_blob where the value and length are
 * block.wire() and block.size().
 */
static int
sqlite3_bind_block(sqlite3_stmt* statement,
                   int index,
                   const Block& block,
                   void(*destructor)(void*))
{
  return sqlite3_bind_blob(statement, index, block.wire(), block.size(), destructor);
}

/**
 * A utility function to generate string by calling the normal sqlite3_column_text.
 */
static string
sqlite3_column_string(sqlite3_stmt* statement, int column)
{
  return string(reinterpret_cast<const char*>(sqlite3_column_text(statement, column)),
                sqlite3_column_bytes(statement, column));
}

/**
 * A utility function to generate block by calling the normal sqlite3_column_text.
 */
static Block
sqlite3_column_block(sqlite3_stmt* statement, int column)
{
  return Block(reinterpret_cast<const char*>(sqlite3_column_blob(statement, column)),
               sqlite3_column_bytes(statement, column));
}

PibDb::PibDb(const string& dbDir)
{
  // Determine the path of PIB DB
  boost::filesystem::path dir;
  if (dbDir == "") {
    dir = boost::filesystem::path(getenv("HOME")) / ".ndn";
    boost::filesystem::create_directories(dir);
  }
  else {
    dir = boost::filesystem::path(dbDir);
    boost::filesystem::create_directories(dir);
  }
  // Open PIB
  int result = sqlite3_open_v2((dir / "pib.db").c_str(), &m_database,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
#ifdef NDN_CXX_DISABLE_SQLITE3_FS_LOCKING
                               "unix-dotfile"
#else
                               0
#endif
                               );

  if (result != SQLITE_OK)
    throw Error("PIB DB cannot be opened/created: " + dbDir);

  // initialize PIB specific tables
  initializeTable("users", INIT_USER_TABLE);
  initializeTable("identities", INIT_ID_TABLE);
  initializeTable("keys", INIT_KEY_TABLE);
  initializeTable("certificates", INIT_CERT_TABLE);
}

void
PibDb::addRootUser(const IdentityCertificate& certificate)
{
  const Name& keyName = certificate.getPublicKeyName();

  // Name of root mgmt key should be "/localhost/pib/user/[KeyID]"
  if (keyName.size() != 4 || keyName.getPrefix(3) != "/localhost/pib/user")
    throw Error("PibDb::addRootUser: supplied certificate is wrong");

  addUser(ROOT, certificate);

  onUserChanged(ROOT);
}

void
PibDb::addUser(const IdentityCertificate& certificate)
{
  const Name& keyName = certificate.getPublicKeyName();

  // Name of user mgmt key should be "/localhost/pib/user/[UserName]/[KeyID]"
  if (keyName.size() != 5 || keyName.getPrefix(3) != "/localhost/pib/user")
    throw Error("PibDb::addUser: supplied certificate is wrong");

  string user = keyName.get(3).toUri();

  // explicit root is not allowed.
  if (boost::iequals(user, "root"))
    throw Error("PibDb::addUser: user name 'root' is invalid");

  addUser(user, certificate);

  onUserChanged(user);
}

void
PibDb::addUser(const std::string& userName, const IdentityCertificate& certificate)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "INSERT OR REPLACE INTO users (user, local_management_cert) \
                      VALUES (?, ?)",
                     -1, &statement, 0);

  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, certificate.wireEncode(), SQLITE_TRANSIENT);

  sqlite3_step(statement);

  sqlite3_finalize(statement);
}

void
PibDb::deleteUser(const std::string& userName)
{
  if (!hasUser(userName))
    return;

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database, "DELETE FROM users WHERE user=?", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);


  sqlite3_prepare_v2(m_database,
                     "DELETE FROM identities WHERE user=?", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  sqlite3_prepare_v2(m_database,
                     "DELETE FROM keys WHERE user=?", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  sqlite3_prepare_v2(m_database,
                     "DELETE FROM certificates WHERE user=?", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  onUserChanged(userName);
}

bool
PibDb::hasUser(const std::string& userName) const
{
  sqlite3_stmt* statement;

  sqlite3_prepare_v2(m_database, "SELECT user FROM users WHERE user=?", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_ROW)
    return true;
  else
    return false;
}


shared_ptr<IdentityCertificate>
PibDb::getUserMgmtCertificate(const std::string& userName) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT local_management_cert FROM users WHERE user=?",
                     -1, &statement, 0);

  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);

  int result = sqlite3_step(statement);

  if (result == SQLITE_ROW) {
    shared_ptr<IdentityCertificate> certificate = make_shared<IdentityCertificate>();
    certificate->wireDecode(Block(static_cast<const uint8_t*>(sqlite3_column_blob(statement, 0)),
                                  sqlite3_column_bytes(statement, 0)));
    sqlite3_finalize(statement);
    return certificate;
  }
  else {
    sqlite3_finalize(statement);
    return shared_ptr<IdentityCertificate>();
  }
}

void
PibDb::listUsers(set<string>& users) const
{
  users.clear();

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database, "SELECT user FROM users", -1, &statement, 0);
  while (sqlite3_step(statement) == SQLITE_ROW)
    users.insert(sqlite3_column_string(statement, 0));

  sqlite3_finalize(statement);
}

void
PibDb::addIdentity(const string& userName, const Name& identity)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "INSERT INTO identities (user, identity) values (?, ?)", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}

void
PibDb::deleteIdentity(const string& userName, const Name& identity)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "DELETE FROM certificates WHERE identity=? AND user=?", -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  sqlite3_prepare_v2(m_database,
                     "DELETE FROM keys WHERE identity=? AND user=?", -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  sqlite3_prepare_v2(m_database,
                     "DELETE FROM identities WHERE identity=? AND user=?", -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}

bool
PibDb::hasIdentity(const string& userName, const Name& identity) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT identity FROM identities WHERE identity=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_ROW)
    return true;
  else
    return false;
}

void
PibDb::setDefaultIdentityOfUser(const string& userName, const Name& identity)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database, "UPDATE users SET default_identity=? WHERE user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  while (sqlite3_step(statement) == SQLITE_ROW) {
  }
  sqlite3_finalize(statement);
}

Name
PibDb::getDefaultIdentityOfUser(const std::string& userName) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database, "SELECT default_identity FROM users WHERE user=?",
                     -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  int result = sqlite3_step(statement);

  if (result == SQLITE_ROW && sqlite3_column_bytes(statement, 0) != 0) {
    Name identity(sqlite3_column_block(statement, 0));
    sqlite3_finalize(statement);
    return identity;
  }
  else {
    sqlite3_finalize(statement);
    throw Error("PibDb::getUserDefaultIdentity: no default identity");
  }
}

void
PibDb::listIdentitiesOfUser(const string& userName, vector<Name>& identities) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT identity FROM identities WHERE user=?", -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);

  identities.clear();
  while (sqlite3_step(statement) == SQLITE_ROW) {
    Name name(sqlite3_column_block(statement, 0));
    identities.push_back(name);
  }
  sqlite3_finalize(statement);
}

void
PibDb::addKey(const string& userName,
              const Name& identity,
              const name::Component& keyId,
              const PublicKey& key)
{
  if (!hasIdentity(userName, identity))
    addIdentity(userName, identity);

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "INSERT INTO keys (user, identity, key_id, key_type, key_bits) \
                      values (?, ?, ?, ?, ?)",
                     -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 3, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_int(statement, 4, key.getKeyType());
  sqlite3_bind_blob(statement, 5, key.get().buf(), key.get().size(), SQLITE_STATIC);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}

shared_ptr<PublicKey>
PibDb::getKey(const std::string& userName,
              const Name& identity,
              const name::Component& keyId) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT key_bits FROM keys WHERE identity=? AND key_id=? AND user=?"
                     , -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);

  if (sqlite3_step(statement) == SQLITE_ROW) {
    shared_ptr<PublicKey> key =
      make_shared<PublicKey>(static_cast<const uint8_t*>(sqlite3_column_blob(statement, 0)),
                             sqlite3_column_bytes(statement, 0));
    sqlite3_finalize(statement);
    return key;
  }
  else {
    sqlite3_finalize(statement);
    return shared_ptr<PublicKey>();
  }
}

void
PibDb::deleteKey(const std::string& userName,
                 const Name& identity,
                 const name::Component& keyId)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "DELETE FROM certificates WHERE identity=? AND key_id=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  sqlite3_prepare_v2(m_database,
                     "DELETE FROM keys WHERE identity=? AND key_id=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (sqlite3_changes(m_database) > 0)
    onKeyDeleted(userName, identity, keyId);
}

bool
PibDb::hasKey(const std::string& userName,
              const Name& identity,
              const name::Component& keyId) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT key_bits FROM keys WHERE identity=? AND key_id=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);
  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_ROW)
    return true;
  else
    return false;
}

void
PibDb::setDefaultKeyNameOfIdentity(const std::string& userName,
                                   const Name& identity,
                                   const name::Component& keyId)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "UPDATE identities SET default_key_id=? WHERE identity=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);
  while (sqlite3_step(statement) == SQLITE_ROW) {
  }
  sqlite3_finalize(statement);
}

Name
PibDb::getDefaultKeyNameOfIdentity(const std::string& userName, const Name& identity) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT default_key_id FROM identities WHERE identity=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);

  if (sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_bytes(statement, 0) != 0) {
    Name keyName = identity;
    keyName.append(sqlite3_column_block(statement, 0));
    sqlite3_finalize(statement);
    return keyName;
  }
  else {
    sqlite3_finalize(statement);
    throw Error("PibDb::getIdentityDefaultKeyName: no default key is set");
  }
}

void
PibDb::listKeyNamesOfIdentity(const string& userName,
                              const Name& identity, vector<Name>& keyNames) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT key_id FROM keys WHERE identity=? AND user=?", -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);

  keyNames.clear();
  while (sqlite3_step(statement) == SQLITE_ROW) {
    Name keyName = identity;
    keyName.append(sqlite3_column_block(statement, 0));
    keyNames.push_back(keyName);
  }
  sqlite3_finalize(statement);
}


void
PibDb::addCertificate(const string& userName, const IdentityCertificate& certificate)
{
  const Name& certName = certificate.getName();
  const Name& keyName = certificate.getPublicKeyName();
  Name identity = keyName.getPrefix(-1);
  const name::Component keyId = keyName[-1];

  if (!hasKey(userName, identity, keyId))
    addKey(userName, identity, keyId, certificate.getPublicKeyInfo());

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "INSERT INTO certificates \
                      (user, certificate_name, identity, key_id, certificate_data) \
                      values (?, ?, ?, ?, ?)",
                     -1, &statement, 0);
  sqlite3_bind_string(statement, 1, userName, SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, certName.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 3, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 4, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 5, certificate.wireEncode(), SQLITE_STATIC);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}

shared_ptr<IdentityCertificate>
PibDb::getCertificate(const std::string& userName, const Name& certificateName) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT certificate_data FROM certificates WHERE certificate_name=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, certificateName.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);

  if (sqlite3_step(statement) == SQLITE_ROW) {
    shared_ptr<IdentityCertificate> certificate = make_shared<IdentityCertificate>();
    certificate->wireDecode(Block(static_cast<const uint8_t*>(sqlite3_column_blob(statement, 0)),
                                  sqlite3_column_bytes(statement, 0)));
    sqlite3_finalize(statement);
    return certificate;
  }
  else {
    sqlite3_finalize(statement);
    return shared_ptr<IdentityCertificate>();
  }
}

void
PibDb::deleteCertificate(const std::string& userName, const Name& certificateName)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "DELETE FROM certificates WHERE certificate_name=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, certificateName.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  sqlite3_step(statement);
  sqlite3_finalize(statement);
}

bool
PibDb::hasCertificate(const std::string& userName, const Name& certificateName) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT certificate_data FROM certificates WHERE certificate_name=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, certificateName.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 2, userName, SQLITE_TRANSIENT);
  int result = sqlite3_step(statement);
  sqlite3_finalize(statement);

  if (result == SQLITE_ROW)
    return true;
  else
    return false;
}

void
PibDb::setDefaultCertNameOfKey(const std::string& userName,
                               const Name& identity,
                               const name::Component& keyId,
                               const Name& certificateName)
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "UPDATE keys SET default_cert_name=? WHERE identity=? AND key_id=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, certificateName.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 3, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 4, userName, SQLITE_TRANSIENT);
  while (sqlite3_step(statement) == SQLITE_ROW) {
  }
  sqlite3_finalize(statement);
}

Name
PibDb::getDefaultCertNameOfKey(const std::string& userName,
                               const Name& identity,
                               const name::Component& keyId) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT default_cert_name FROM keys WHERE identity=? AND key_id=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);

  if (sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_bytes(statement, 0) != 0) {
    Name certName(sqlite3_column_block(statement, 0));
    sqlite3_finalize(statement);
    return certName;
  }
  else {
    sqlite3_finalize(statement);
    throw Error("PibDb::getDefaultCertNameOfKey: no default cert is set");
  }
}

void
PibDb::listCertNamesOfKey(const string& userName,
                          const Name& identity, const name::Component& keyId,
                          vector<Name>& certNames) const
{
  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database,
                     "SELECT certificate_name FROM certificates \
                      WHERE identity=? AND key_id=? AND user=?",
                     -1, &statement, 0);
  sqlite3_bind_block(statement, 1, identity.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_block(statement, 2, keyId.wireEncode(), SQLITE_TRANSIENT);
  sqlite3_bind_string(statement, 3, userName, SQLITE_TRANSIENT);

  certNames.clear();
  while (sqlite3_step(statement) == SQLITE_ROW) {
    Name name(sqlite3_column_block(statement, 0));
    certNames.push_back(name);
  }
  sqlite3_finalize(statement);
}

// Private methods

bool
PibDb::initializeTable(const string& tableName, const string& initCommand)
{
  // Check if the table exists;
  bool doesTableExist = false;
  string checkingString =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='" + tableName + "'";

  sqlite3_stmt* statement;
  sqlite3_prepare_v2(m_database, checkingString.c_str(), -1, &statement, 0);

  int result = sqlite3_step(statement);
  if (result == SQLITE_ROW)
    doesTableExist = true;
  sqlite3_finalize(statement);

  // Create the table if it does not exist
  if (!doesTableExist) {
    char* errorMessage = 0;
    result = sqlite3_exec(m_database, initCommand.c_str(), NULL, NULL, &errorMessage);

    if (result != SQLITE_OK && errorMessage != 0) {
      sqlite3_free(errorMessage);
      return false;
    }
  }

  return true;
}

} // namespace pib
} // namespace ndn

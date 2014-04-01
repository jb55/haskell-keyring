-- Copyright (c) 2014 Sebastian Wiesner <lunaryorn@gmail.com>

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.

-- |Access to keyrings of Unix systems.
--
-- Currently this module only supports KWallet, via "System.Keyring.Unix.KDE".
--
-- This module and any of its submodules are not available on OS X.  See
-- "System.Keyring.Darwin" for keyring support on OS X.
module System.Keyring.Unix (getPassword,setPassword) where

import qualified System.Keyring.Unix.KDE as KDE

import System.Keyring.Types

import Control.Exception (throwIO,handleJust)
import Control.Monad (liftM)
import System.Environment (getEnv)
import System.IO.Error (isDoesNotExistError)

getEnvSafe :: String -> IO (Maybe String)
getEnvSafe env =
  handleJust isVariableMissing (\_ -> return Nothing) (liftM Just (getEnv env))
  where isVariableMissing e =
          if isDoesNotExistError e then Just () else Nothing


-- |The keyring provider to use.
--
-- Throws 'KeyringMissingBackendError' if no keyring backend is available on the
-- current system.
provider :: IO (Service -> Username -> IO (Maybe Password)
               ,Service -> Username -> Password -> IO ())
provider = do
  desktop <- getEnvSafe "XDG_CURRENT_DESKTOP"
  case desktop of
    Just "KDE" -> return (KDE.getPassword, KDE.setPassword)
    _ -> throwIO KeyringMissingBackendError

-- |@'getPassword' service username@ gets a password from the current keyring.
--
-- @username@ is the name of the user whose password to get.  @service@
-- identifies the application which fetches the password.
--
-- This function throws 'KeyringMissingBackendError' is no keyring
-- implementation exists for the current system and environment, and
-- 'KeyringError' if access to the keyring failed.
getPassword :: Service -> Username -> IO (Maybe Password)
getPassword service username = do
  (get, _) <- provider
  get service username

-- |@'setPassword' service username password@ adds @password@ for @username@
-- to the current keyring.
--
-- @username@ is the name of the user whose password to set.  @service@
-- identifies the application which sets the password.
--
-- This function throws 'KeyringMissingBackendError' is no keyring
-- implementation exists for the current system and environment, and
-- 'KeyringError' if access to the keyring failed.
setPassword :: Service -> Username -> Password -> IO ()
setPassword service username password = do
  (_, set) <- provider
  set service username password

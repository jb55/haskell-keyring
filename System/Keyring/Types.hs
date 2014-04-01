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

{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE DeriveDataTypeable #-}

-- |Basic types for keyring access.
module System.Keyring.Types
       (
         -- * Data types
         Service(..)
       , Username(..)
       , Password(..)
         -- * Exceptions
       , KeyringError(..)
       , KeyringMissingBackendError(..)
       )
       where

import Control.Exception (SomeException,Exception(..))
import Data.Typeable (Typeable,cast)

-- |A service which uses the keyring
--
-- The service identifies the application or service for which a secret is
-- stored.
newtype Service = Service String

-- |A username
newtype Username = Username String

-- |A password
newtype Password = Password String

-- |Base type for all exceptions of this library.
data KeyringError = forall e . Exception e => KeyringError e
                  deriving Typeable

instance Show KeyringError where
  show (KeyringError e) = show e

instance Exception KeyringError

data KeyringMissingBackendError =
  -- |@'KeyringMissingBackendError'@ indicates that no keyring backend is
  -- available for the current system and environment.
  --
  -- See "System.Keyring" for a list of supported keyring backends.
  KeyringMissingBackendError deriving (Typeable)

instance Show KeyringMissingBackendError where
  show KeyringMissingBackendError = "Keyring error: no backend available"

instance Exception KeyringMissingBackendError where
  toException = toException . KeyringError
  fromException x = do
    KeyringError e <- fromException x
    cast e

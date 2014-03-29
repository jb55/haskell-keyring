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

{-# OPTIONS_HADDOCK hide #-}

{-# LANGUAGE ForeignFunctionInterface #-}

-- |Access to the OS X Key chain
module System.Keyring.Darwin (setPassword,getPassword) where

import System.Keyring.Types

import qualified Data.ByteString.UTF8 as UTF8

import Data.ByteString
import Data.Int (Int32)
import Data.Word (Word32)
import Foreign.C
import Foreign.Ptr
import Foreign.Storable
import Foreign.Marshal.Alloc

-- C declarations

#include <Security/Security.h>

type CFTypeRef = Ptr ()
type SecKeychainItemRef = Ptr ()
type SecKeychainRef = Ptr ()
type OSStatus = #type OSStatus
type UInt32 = #type UInt32

#{enum OSStatus, ,
  errSecSuccess = errSecSuccess,
  errSecItemNotFound = errSecItemNotFound}

foreign import ccall unsafe "Security/Security.h SecKeychainItemFreeContent"
  c_SecKeychainItemFreeContent :: Ptr () -> CString -> IO OSStatus

foreign import ccall unsafe "Security/Security.h SecKeychainFindGenericPassword"
  c_SecKeychainFindGenericPassword :: CFTypeRef
                                   -> UInt32 -> CString
                                   -> UInt32 -> CString
                                   -> Ptr UInt32 -> Ptr CString
                                   -> Ptr SecKeychainItemRef
                                   -> IO OSStatus

foreign import ccall unsafe "Security/Security.h SecKeychainAddGenericPassword"
  c_SecKeychainAddGenericPassword :: SecKeychainRef
                                  -> UInt32 -> CString
                                  -> UInt32 -> CString
                                  -> UInt32 -> CString
                                  -> Ptr SecKeychainItemRef
                                  -> IO OSStatus

-- C wrappers

throwKeychainError :: OSStatus -> IO a
throwKeychainError _ =
  -- FIXME: Use custom error type
  -- FIXME: Extract error message
  ioError (userError "Keychain failed")

secKeychainFindGenericPassword :: ByteString -> ByteString -> IO (Maybe ByteString)
secKeychainFindGenericPassword service username = do
  useAsCStringLen service withService
  where
    withService c_service = useAsCStringLen username (withServiceAndUser c_service)
    withServiceAndUser c_service c_user = alloca (withPwLen c_service c_user)
    withPwLen c_service c_user pwlen = alloca (withAll c_service c_user pwlen)
    withAll :: CStringLen -> CStringLen -> Ptr UInt32 -> Ptr CString -> IO (Maybe ByteString)
    withAll (c_service_b, c_service_l) (c_user_b, c_user_l) password_l_buf password_buf =
      do
        result <- c_SecKeychainFindGenericPassword
                   nullPtr      -- Default keychain
                   (fromIntegral c_service_l) c_service_b
                   (fromIntegral c_user_l) c_user_b
                   password_l_buf password_buf
                   nullPtr      -- Ignore the item reference
        case result of
          _ | result == errSecSuccess -> do
            password_b <- peek password_buf
            password_l <- peek password_l_buf
            password <- packCStringLen (password_b, fromIntegral password_l)
            _ <- c_SecKeychainItemFreeContent nullPtr password_b
            return (Just password)
          _ | result == errSecItemNotFound -> return Nothing
          _ -> throwKeychainError result

secKeychainAddGenericPassword :: ByteString -> ByteString -> ByteString -> IO ()
secKeychainAddGenericPassword service username password = do
  useAsCStringLen service withService
  where
    withService c_service = useAsCStringLen username (withServiceAndUser c_service)
    withServiceAndUser c_service c_username =
      useAsCStringLen password (withAll c_service c_username)
    withAll (c_service_b, c_service_l) (c_user_b, c_user_l) (c_pw_b, c_pw_l) = do
      result <- c_SecKeychainAddGenericPassword
                nullPtr         -- Default keychain
                (fromIntegral c_service_l) c_service_b
                (fromIntegral c_user_l) c_user_b
                (fromIntegral c_pw_l) c_pw_b
                nullPtr         -- Ignore the item
      if result == errSecSuccess then return () else throwKeychainError result

-- Public API

-- |@'setPassword' service username password@ stores a @password@ for a given
-- @username@ and @service@.
setPassword :: Service -> Username -> Password -> IO ()
setPassword (Service service) (Username username) (Password password) =
  secKeychainAddGenericPassword service_bytes username_bytes password_bytes
  where service_bytes = UTF8.fromString service
        username_bytes = UTF8.fromString username
        password_bytes = UTF8.fromString password

-- |@'getPassword' service username@ gets password for a given @username@ and
-- @service@.  If the password was not found, return 'Nothing' instead.
getPassword :: Service -> Username -> IO (Maybe Password)
getPassword (Service service) (Username username) = do
  password_bytes <- secKeychainFindGenericPassword service_bytes username_bytes
  return (fmap Password (fmap (UTF8.toString) password_bytes))
  where service_bytes = UTF8.fromString service
        username_bytes = UTF8.fromString username

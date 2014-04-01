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

{-# LANGUAGE DeriveDataTypeable #-}

-- |Access to KWallet.
module System.Keyring.Unix.KDE
       (
         -- * KWallet access
         getPassword,setPassword
         -- * Error handling
       , KWalletError(..)) where

import System.Keyring.Types

import Control.Exception (Exception,throwIO,bracket,catch)
import Control.Monad (void,unless)
import Data.Int (Int32)
import Data.Typeable (Typeable)
import Network.DBus (DBusConnection,BusName(..)
                    ,DBusCall(..),ObjectPath(..),Interface(..),Member(..)
                    ,DBusTypeable(..),Type(..),DBusValue(..)
                    ,DBusError(..),ErrorName(..)
                    ,busGetSession,establish,authenticateWithRealUID,call
                    ,returnBody,packedStringToString)
import Text.Printf (printf)

data KWalletError = KWalletDBusError ErrorName (Maybe String)
                    -- ^An error received over DBus error, with an error name
                    -- and a message
                  | KWalletOperationError String
                    -- ^A KWallet operation failed, with a message
                  | KWalletInvalidReturn
                    [Type]      -- ^The expected return signature
                    [Type]      -- ^The actual return signature
                    -- ^An unexpected return value was received.
                  deriving Typeable

instance Show KWalletError where
  show (KWalletDBusError (ErrorName name) Nothing) =
    "KWallet error: DBus error " ++ name
  show (KWalletDBusError (ErrorName name) (Just message)) =
    printf "KWallet error: DBus error %s: %s" name message
  show (KWalletOperationError message) =
    "KWallet error: Operation failed: " ++ message
  show (KWalletInvalidReturn expected actual) =
    printf "KWallet error: invalid return: expected %s, got %s" (show expected) (show actual)

instance Exception KWalletError

throwInvalidReturn :: [Type] -> [DBusValue] -> IO a
throwInvalidReturn expected actual =
  throwIO (KWalletInvalidReturn expected (map toSignature actual))

getKWalletKey :: AppID -> Username -> String
getKWalletKey (AppID appID) (Username username) = username ++ "@" ++ appID

withSessionBus :: (DBusConnection -> IO a) -> IO a
withSessionBus actions = connectSession >>= actions
  where connectSession = establish busGetSession authenticateWithRealUID

newtype AppID = AppID String

instance DBusTypeable AppID where
  toSignature (AppID appID) = toSignature appID
  toDBusValue (AppID appID) = toDBusValue appID
  fromDBusValue value = fmap AppID (fromDBusValue value)

newtype Wallet = Wallet Int32

instance DBusTypeable Wallet where
  toSignature (Wallet appID) = toSignature appID
  toDBusValue (Wallet appID) = toDBusValue appID
  fromDBusValue value = fmap Wallet (fromDBusValue value)

callKWalletD :: DBusConnection -> String -> [DBusValue] -> IO [DBusValue]
callKWalletD connection methodName args = do
  result <- catch (call connection busName message) (throwIO.wrapDBusError)
  return (returnBody result)
  where busName = BusName {unBusName = "org.kde.kwalletd"}
        path = ObjectPath { unObjectPath = "/modules/kwalletd" }
        interface = Interface { unInterface = "org.kde.KWallet" }
        member = Member { unMember = methodName }
        message = DBusCall { callPath = path
                           , callInterface = Just interface
                           , callMember = member
                           , callBody = args}
        wrapDBusError DBusError{errorName=name,errorBody=body} =
          case body of
            [DBusString errMsg] ->
              KWalletDBusError name (Just (packedStringToString errMsg))
            _ -> KWalletDBusError name Nothing

openWallet :: DBusConnection -> String -> AppID -> IO Wallet
openWallet connection walletName appID = do
  reply <- callKWalletD connection "open" [toDBusValue walletName
                                          ,DBusInt64 0
                                          ,toDBusValue appID]
  case reply of
    [DBusInt32 handle] -> return (Wallet handle)
    _ -> throwInvalidReturn [SigInt32] reply

closeWallet :: DBusConnection -> AppID -> Wallet -> IO ()
closeWallet connection appID wallet =
  void (callKWalletD connection "close" [toDBusValue wallet
                                        ,toDBusValue False
                                        ,toDBusValue appID])

withNetworkWallet :: AppID -> (DBusConnection -> Wallet -> IO a) -> IO a
withNetworkWallet appID action = withSessionBus openNetworkWallet
  where
    openNetworkWallet connection = do
      reply <- callKWalletD connection "networkWallet" []
      case reply of
        [DBusString name] -> runAction connection (packedStringToString name)
        _ -> throwInvalidReturn [SigString] reply
    runAction connection name = bracket
      (openWallet connection name appID)
      (closeWallet connection appID)
      (action connection)

-- |@'getPassword' service username@ gets a password from the user's network
-- wallet.
--
-- @username@ is the name of the user whose password to get.  @service@
-- identifies the application which fetches the password.
getPassword :: Service -> Username -> IO (Maybe Password)
getPassword (Service service) username = withNetworkWallet appID fetchPassword
  where
    appID = AppID service
    key = getKWalletKey appID username
    fetchPassword connection wallet = do
      hasPassword <- hasEntry connection wallet
      if hasPassword then readPassword connection wallet else return Nothing
    hasEntry connection wallet = do
      reply <- callKWalletD connection "hasEntry" [toDBusValue wallet
                                                  ,toDBusValue "Passwords"
                                                  ,toDBusValue key
                                                  ,toDBusValue appID]
      case reply of
        [DBusBoolean b] -> return b
        _ -> throwInvalidReturn [SigBool] reply
    readPassword connection wallet = do
      reply <- callKWalletD connection "readPassword" [toDBusValue wallet
                                                      ,toDBusValue "Passwords"
                                                      ,toDBusValue key
                                                      ,toDBusValue appID]
      case reply of
        [DBusString s] -> return (Just (Password (packedStringToString s)))
        _ -> throwInvalidReturn [SigString] reply


-- |@'setPassword' service username password@ adds @password@ for @username@ to
-- the user's network wallet.
--
-- @username@ is the name of the user whose password to set.  @service@
-- identifies the application which sets the password.
setPassword :: Service -> Username -> Password -> IO ()
setPassword (Service service) username (Password password) =
  withNetworkWallet appID storePassword
  where
    appID = AppID service
    key = getKWalletKey appID username
    storePassword connection wallet = do
      folderExists <- hasFolder connection wallet
      unless folderExists (createFolder connection wallet)
      writePassword connection wallet
    hasFolder connection wallet = do
      reply <- callKWalletD connection "hasFolder" [toDBusValue wallet
                                                   ,toDBusValue "Passwords"
                                                   ,toDBusValue appID]
      case reply of
        [DBusBoolean b] -> return b
        _ -> throwInvalidReturn [SigBool] reply
    createFolder connection wallet = do
      reply <- callKWalletD connection "createFolder" [toDBusValue wallet
                                                      ,toDBusValue "Passwords"
                                                      ,toDBusValue appID]
      case reply of
        [DBusBoolean b] -> do
          unless b (throwIO (KWalletOperationError "Could not create Passwords folder"))
          return ()
        _ -> throwInvalidReturn [SigBool] reply
    writePassword connection wallet =
      void $ callKWalletD connection "writePassword" [toDBusValue wallet
                                                     ,toDBusValue "Passwords"
                                                     ,toDBusValue key
                                                     ,toDBusValue password
                                                     ,toDBusValue appID]

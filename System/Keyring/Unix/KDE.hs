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

{-# OPTIONS_HADDOCK hide #-}

-- |Access to the KDE keychain
module System.Keyring.Unix.KDE (getPassword,setPassword) where

import System.Keyring.Types

import Control.Exception (Exception,throwIO,bracket,catch)
import Control.Monad (void)
import Data.Int (Int32)
import Data.Typeable (Typeable)
import Network.DBus (DBusConnection,BusName(..)
                    ,DBusCall(..),ObjectPath(..),Interface(..),Member(..)
                    ,DBusTypeable(..),Type(..),DBusValue(..)
                    ,DBusError(..),ErrorName(..)
                    ,busGetSession,establish,authenticateWithRealUID,call
                    ,returnBody,packedStringToString)
import Text.Printf (printf)

data KWalletException = KWalletDBusError ErrorName (Maybe String)
                      | KWalletInvalidReturn [Type] [Type]
                      deriving Typeable

instance Show KWalletException where
  show (KWalletDBusError (ErrorName name) Nothing) =
    printf "KWallet error: DBus error %s" name
  show (KWalletDBusError (ErrorName name) (Just message)) =
    printf "KWallet error: DBus error %s: %s" name message
  show (KWalletInvalidReturn expected actual) =
    printf "KWallet error: invalid return: expected %s, got %s" (show expected) (show actual)

instance Exception KWalletException

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

getPassword :: Service -> Username -> IO (Maybe Password)
getPassword (Service service) username = withNetworkWallet appID readPassword
  where
    appID = AppID service
    key = getKWalletKey appID username
    readPassword connection wallet = do
      reply <- callKWalletD connection "readPassword" [toDBusValue wallet
                                                      ,toDBusValue "Passwords"
                                                      ,toDBusValue key
                                                      ,toDBusValue appID]
      case reply of
        [DBusString s] -> return $ case packedStringToString s of
          [] -> Nothing
          pw -> Just (Password pw)
        _ -> throwInvalidReturn [SigString] reply

setPassword :: Service -> Username -> Password -> IO ()
setPassword (Service service) username (Password password) =
  withNetworkWallet appID writePassword
  where
    appID = AppID service
    key = getKWalletKey appID username
    writePassword connection wallet =
      void $ callKWalletD connection "writePassword" [toDBusValue wallet
                                                     ,toDBusValue "Passwords"
                                                     ,toDBusValue key
                                                     ,toDBusValue password
                                                     ,toDBusValue appID]

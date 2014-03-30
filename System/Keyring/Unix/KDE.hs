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

import Control.Exception (Exception,throwIO,bracket)
import Control.Monad (void)
import Data.Maybe (fromJust)
import Data.Int (Int32,Int64)
import Data.Typeable (Typeable)
import DBus
import DBus.Client
import Prelude hiding (error)
import Text.Printf (printf)

data KWalletException = KWalletException ErrorName String
                      deriving Typeable

instance Show KWalletException where
  show (KWalletException name message) =
    printf "KWallet error: %s: %s" (formatErrorName name) message

instance Exception KWalletException

getKWalletKey :: Service -> Username -> String
getKWalletKey (Service service) (Username username) = username ++ "@" ++ service

withSessionBus :: (Client -> IO a) -> IO a
withSessionBus = bracket connectSession disconnect


newtype AppID = AppID String

instance IsVariant AppID where
  toVariant (AppID appID) = toVariant appID
  fromVariant value = fmap AppID (fromVariant value)

newtype Wallet = Wallet Int32

instance IsVariant Wallet where
  toVariant (Wallet handle) = toVariant handle
  fromVariant value = fmap Wallet (fromVariant value)

callKWalletD :: Client -> String -> [Variant] -> IO [Variant]
callKWalletD client methodName args = do
  result <- call client message
  case result of
    Left error -> throwIO (KWalletException
                           (methodErrorName error)
                           (methodErrorMessage error))
    Right reply -> return (methodReturnBody reply)
  where memberName = memberName_ methodName
        path = objectPath_ "/modules/kwalletd"
        interface = interfaceName_ "org.kde.KWallet"
        busName = busName_ "org.kde.kwalletd"
        message = (methodCall path interface memberName) {
          methodCallDestination = Just busName,
          methodCallBody = args}

openWallet :: Client -> String -> AppID -> IO Wallet
openWallet client walletName appID = do
  reply <- callKWalletD client "open" [toVariant walletName
                                      , toVariant (0::Int64)
                                      , toVariant appID]
  return (fromJust (fromVariant (head reply)))

closeWallet :: Client -> AppID -> Wallet -> IO ()
closeWallet client appID wallet =
  void (callKWalletD client "close" [toVariant wallet
                                    ,toVariant False
                                    ,toVariant appID])

withNetworkWallet :: Service -> (Client -> Wallet -> IO a) -> IO a
withNetworkWallet (Service service) action = withSessionBus openNetworkWallet
  where
    openNetworkWallet client = do
      reply <- callKWalletD client "networkWallet" []
      let name = fromJust (fromVariant (head reply))
      runAction client name
    runAction client name = bracket
      (openWallet client name (AppID service))
      (closeWallet client (AppID service))
      (action client)

getPassword :: Service -> Username -> IO (Maybe Password)
getPassword service username = withNetworkWallet service readPassword
  where
    key = getKWalletKey service username
    readPassword client wallet = do
      let (Service appID) = service
      reply <- callKWalletD client "readPassword" [toVariant wallet
                                                  ,toVariant "Passwords"
                                                  ,toVariant key
                                                  ,toVariant appID]
      return $ case fromVariant (head reply) of
        Nothing -> Nothing
        Just [] -> Nothing
        Just pw -> Just (Password pw)

setPassword :: Service -> Username -> Password -> IO ()
setPassword service username (Password password) =
  withNetworkWallet service writePassword
  where
    key = getKWalletKey service username
    writePassword client wallet = do
      let (Service appID) = service
      void $ callKWalletD client "writePassword" [toVariant wallet
                                                 ,toVariant "Passwords"
                                                 ,toVariant key
                                                 ,toVariant password
                                                 ,toVariant appID]

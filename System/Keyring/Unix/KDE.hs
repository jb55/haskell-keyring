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

-- |Access to the KDE keychain
module System.Keyring.Unix.KDE (getPassword,setPassword) where

import System.Keyring.Types

import Control.Exception (bracket)
import Control.Monad (void)
import System.Exit (ExitCode(ExitSuccess))
import System.Process (readProcessWithExitCode)

callKWallet :: String -> [String] -> IO (Maybe String)
callKWallet method methodArgs = do
  output <- readProcessWithExitCode "qdbus-qt4" args []
  return $ case output of
    (ExitSuccess, stdout, _) -> Just (head (lines stdout))
    _ -> Nothing
  where args = (["org.kde.kwalletd", "/modules/kwalletd", method]
                ++ methodArgs)

openNetworkKWallet :: Service -> IO (Maybe String)
openNetworkKWallet (Service service) = do
  walletName <- callKWallet "networkWallet" [service]
  maybe (return Nothing) openWallet walletName
  where
    openWallet name = callKWallet "open" [name, "0", service]

closeKWallet :: Service -> String -> IO ()
closeKWallet (Service service) handle =
  void $ callKWallet "close" [handle, service]

withLocalKWallet :: Service -> (String -> IO (Maybe a)) -> IO (Maybe a)
withLocalKWallet service action = bracket (openNetworkKWallet service) close act
  where
    act = maybe (return Nothing) action
    close = maybe (return ()) (closeKWallet service)

getKWalletKey :: Service -> Username -> String
getKWalletKey (Service service) (Username username) = username ++ "@" ++ service

getPassword :: Service -> Username -> IO (Maybe Password)
getPassword service username = withLocalKWallet service (readPassword service)
  where
    key = getKWalletKey service username
    readPassword (Service app) handle = do
      password <- callKWallet "readPassword" [handle, "Passwords", key, app]
      return $ case password of
        Nothing -> Nothing
        Just "" -> Nothing
        Just t  -> Just $ Password t

setPassword :: Service -> Username -> Password -> IO ()
setPassword service username (Password password) =
  void $ withLocalKWallet service (writePassword service)
  where
    key = getKWalletKey service username
    writePassword (Service app) handle =
      callKWallet "writePassword" [handle, "Passwords", key, password, app]

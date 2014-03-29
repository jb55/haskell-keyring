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

{-# OPTIONS_GHC -Wall -O2 #-}

{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiParamTypeClasses #-}

import qualified System.Environment as Env
import qualified System.IO as IO
import qualified System.Console.CmdArgs as Args

import Web.Marmalade

import Control.Exception (bracket)
import Control.Monad (when)
import System.Console.CmdArgs (Data,Typeable,(&=),cmdArgs)
import System.Exit (ExitCode(ExitSuccess,ExitFailure),exitWith)
import System.Process (readProcessWithExitCode,callProcess)
import Text.Printf (printf)

import Paths_marmalade_upload (version)

-- Program information

appName :: String
appName = "marmalade-upload"

appVersion :: String
appVersion = show version

appService :: String
appService = "lunaryorn/" ++ appName

appUserAgent :: String
appUserAgent = appService ++ "/" ++ appVersion

-- CLI tools

withEcho :: Bool -> IO a -> IO a
withEcho echo action = bracket (IO.hGetEcho IO.stdin)
                       (IO.hSetEcho IO.stdin)
                       (const $ IO.hSetEcho IO.stdin echo >> action)

askPassword :: String -> IO String
askPassword prompt = do
  putStr prompt
  IO.hFlush IO.stdout
  password <- withEcho False getLine
  putChar '\n'
  return password

-- Process tools

checkOutput :: String -> [String] -> IO (Either (Int, String) String)
checkOutput executable args = do
  output <- readProcessWithExitCode executable args []
  return $ case output of
             (ExitSuccess, stdout, _)      -> Right stdout
             (ExitFailure code, _, stderr) -> Left (code, stderr)

-- Token storage

#ifdef DARWIN
getToken :: Username -> IO (Maybe Token)
getToken (Username username) = do
  output <- checkOutput "security" ["find-generic-password", "-w"
                                   ,"-a", username
                                   ,"-s", appService]
  return $ case output of
    Left _ -> Nothing -- The item didn't exist
    Right stdout -> Just (Token (head (lines stdout)))

setToken :: Username -> Token -> IO ()
setToken (Username username) (Token token) =
  callProcess "security" ["add-generic-password"
                         ,"-a", username
                         ,"-s", appService
                         ,"-w", token
                         ,"-U"
                         ,"-l", "Marmalade access token"]

#else
callKWallet :: String -> [String] -> IO (Maybe String)
callKWallet method args = do
  output <- checkOutput "qdbus-qt4" (["org.kde.kwalletd"
                                     ,"/modules/kwalletd"
                                     ,method] ++ args)
  case output of
    Left _       -> return Nothing
    Right stdout -> return $ Just (head (lines stdout))

openNetworkKWallet :: IO (Maybe String)
openNetworkKWallet = do
  walletName <- callKWallet "networkWallet" []
  maybe (return Nothing) openWallet walletName
  where
    openWallet name = callKWallet "open" [name, "0", appService]

closeKWallet :: String -> IO ()
closeKWallet handle = void $ callKWallet "close" [handle, appService]

withLocalKWallet :: (String -> IO (Maybe a)) -> IO (Maybe a)
withLocalKWallet action = bracket openNetworkKWallet close act
  where
    act = maybe (return Nothing) action
    close = maybe (return ()) closeKWallet

getKWalletKey :: Username -> String
getKWalletKey (Username username) = username ++ "@" ++ appService

getTokenKDE :: Username -> IO (Maybe Token)
getTokenKDE username = withLocalKWallet getPassword
  where
    getPassword handle = do
      password <- callKWallet "readPassword" [handle, "Passwords"
                                             ,getKWalletKey username
                                             ,appService]
      return $ case password of
        Nothing -> Nothing
        Just "" -> Nothing
        Just t  -> Just $ Token t

setTokenKDE :: Username -> Token -> IO ()
setTokenKDE username (Token token) = void $ withLocalKWallet setPassword
  where
    setPassword handle = callKWallet "writePassword" [handle
                                                     ,"Passwords"
                                                     ,getKWalletKey username
                                                     ,token
                                                     ,appService]

tokenProvider :: IO (Username -> IO (Maybe Token), Username -> Token -> IO ())
tokenProvider = do
  desktop <- Env.getEnv "XDG_CURRENT_DESKTOP"
  return $ case desktop of
    "KDE" -> (getTokenKDE, setTokenKDE)
    _ -> dummy
  where dummy = (\_ -> return Nothing, \_ _ -> return ())

getToken :: Username -> IO (Maybe Token)
getToken username = do
  (getT, _) <- tokenProvider
  getT username

setToken :: Username -> Token -> IO ()
setToken username token = do
  (_, setT) <- tokenProvider
  setT username token
#endif

-- Authentication

askMarmaladePassword :: String -> Marmalade String
askMarmaladePassword username = do
  guard $ askPassword (printf "Marmalade password for %s (never stored): " username)

getAuth :: String -> IO Auth
getAuth username = do
  result <- getToken (Username username)
  return $ case result of
    Just token -> (TokenAuth (Username username) token)
    Nothing -> (BasicAuth (Username username) (askMarmaladePassword username))

-- Arguments handling

exitFailure :: String -> IO ()
exitFailure message = IO.hPutStrLn IO.stderr message >> exitWith (ExitFailure 1)

data Arguments = Arguments { argUsername :: String
                           , argPackageFile :: String}
               deriving (Show, Data, Typeable)

arguments :: IO Arguments
arguments = do
  programName <- Env.getProgName
  return $ Arguments { argUsername = Args.def &= Args.argPos 0
                                     &= Args.typ "USERNAME"
                     , argPackageFile = Args.def &= Args.argPos 1
                                        &= Args.typ "PACKAGE" }
             &= Args.summary (printf "%s %s" programName appVersion)
             &= Args.help "Upload a PACKAGE to Marmalade."
             &= Args.details ["Copyright (C) 2014 Sebastian Wiesner"
                             ,"Distributed under the terms of the MIT/X11 license."]
             &= Args.program programName

main :: IO ()
main = do
  args <- arguments >>= cmdArgs
  auth <- getAuth (argUsername args)
  let mustSaveToken = case auth of
        TokenAuth _ _ -> False
        _             -> True
  result <- runMarmalade appUserAgent auth $ do
    (username, token) <- login
    upload <- uploadPackage (argPackageFile args)
    when mustSaveToken (guard $ setToken username token)
    guard $ putStrLn (uploadMessage upload)
  case result of
    Left e -> exitFailure $ show e
    _ -> return ()

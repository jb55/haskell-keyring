#!/usr/bin/env runhaskell

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

-- Upload packages to Marmalade.
--
-- Requires: cmdargs
--
-- Install these with: cabal install cmdargs http-conduit aeson

{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (mapM_)
import Control.Applicative ((<$>))
import Control.Exception (bracket)
import Control.Monad (liftM,mzero,void)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Foldable (mapM_)
import Data.Aeson (FromJSON,parseJSON
                  ,Value(Object),(.:)
                  ,decode)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Data.Conduit (ResourceT)
import Text.Printf (printf)
import qualified System.Info as SI
import qualified System.IO as IO
import System.Environment (getProgName,getEnv)
import System.Process (readProcessWithExitCode
                      ,createProcess,waitForProcess,proc)
import System.Exit (ExitCode(ExitSuccess,ExitFailure),exitWith)
import System.Console.CmdArgs (Data,Typeable
                              ,cmdArgs,(&=)
                              ,def,argPos,typ,help
                              ,details,summary,program)
import Network.HTTP.Conduit (Manager,withManager,httpLbs
                            ,Request,parseUrl,requestHeaders,urlEncodedBody
                            ,responseBody)
import Network.HTTP.Types.Header (hUserAgent)

-- Program information

appName :: String
appName = "marmalade-upload"

appVersion :: String
appVersion = "0.1"

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

callProcess :: String -> [String] -> IO ()
callProcess executable args = do
  (_, _, _, handle) <- createProcess (proc executable args)
  exitCode <- waitForProcess handle
  case exitCode of
    ExitSuccess -> return ()
    ExitFailure code ->
        let cmd = executable ++ " " ++ unwords args in
        ioError (userError (printf "%s (exit code %d)" cmd code))

checkOutput :: String -> [String] -> IO (Either (Int, String) String)
checkOutput executable args = do
  output <- readProcessWithExitCode executable args []
  return $ case output of
             (ExitSuccess, stdout, _)      -> Right stdout
             (ExitFailure code, _, stderr) -> Left (code, stderr)

-- Token storage

getTokenDarwin :: Username -> IO (Maybe Token)
getTokenDarwin (Username username) = do
    output <- checkOutput "security" ["find-generic-password", "-w"
                                     ,"-a", username
                                     ,"-s", appService]
    return $ case output of
               Left _ -> Nothing -- The item didn't exist
               Right stdout -> Just (Token (head (lines stdout)))

setTokenDarwin :: Username -> Token -> IO ()
setTokenDarwin (Username username) (Token token) =
    callProcess "security" ["add-generic-password"
                           ,"-a", username
                           ,"-s", appService
                           ,"-w", token
                           ,"-U"
                           ,"-l", "Marmalade access token"]

callKWallet :: String -> [String] -> IO (Maybe String)
callKWallet method args = do
  output <-  checkOutput "qdbus-qt4" (["org.kde.kwalletd"
                                      ,"/modules/kwalletd"
                                      ,method] ++ args)
  case output of
    Left _       -> print output >> return Nothing
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
tokenProvider = case SI.os of
                  "darwin" -> return (getTokenDarwin, setTokenDarwin)
                  "linux" -> do
                             desktop <- getEnv "XDG_CURRENT_DESKTOP"
                             return $ case desktop of
                               "KDE" -> (getTokenKDE, setTokenKDE)
                               _ -> dummy
                  _ -> return dummy
    where
      dummy = (\_ -> return Nothing, \_ _ -> return ())

getToken :: Username -> IO (Maybe Token)
getToken username = do
  (get, _) <- tokenProvider
  get username

setToken :: Username -> Token -> IO ()
setToken username token = do
  (_, set) <- tokenProvider
  set username token

-- Marmalade access

newtype Username = Username String deriving (Show, Eq)
newtype Token = Token String deriving (Show, Eq)

instance FromJSON Token where
    parseJSON (Object o) = Token <$> (o .: "token")
    parseJSON _          = mzero

marmaladeURL :: String
marmaladeURL = "http://marmalade-repo.org"

makeRequest :: String -> ResourceT IO Request
makeRequest endpoint = do
  initReq <- parseUrl (marmaladeURL ++ endpoint)
  return initReq { requestHeaders = [(hUserAgent, UTF8.fromString appUserAgent)] }

login :: Manager -> Username -> ResourceT IO (Maybe Token)
login manager (Username username) = do
  password <- liftIO $ askPassword (printf "Marmalade password for %s (never stored): "
                                           username)
  request <- liftM (urlEncodedBody [("name", UTF8.fromString username)
                                   ,("password", UTF8.fromString password)])
             (makeRequest "/v1/users/login")
  response <- httpLbs request manager
  let token = decode (responseBody response)
  liftIO $ mapM_ (setToken (Username username)) token
  return token

doUpload :: Manager -> Username -> Package -> ResourceT IO ()
doUpload manager username package = do
  storedToken <- liftIO $ getToken username
  token <- maybe (login manager username) (return.Just) storedToken
  liftIO $ print token

-- Package handling

data Package = Package { packageFileName :: String
                       , packageContents :: BS.ByteString }

packageMimeTypes :: [String]
packageMimeTypes = ["application/x-tar", "text/x-lisp"]

verifyMimeType :: String -> IO (Maybe String)
verifyMimeType package = do
  output <- checkOutput "file" ["--brief" ,"--mime-type", package]
  return $ case output of
             Left (code, err) ->
                 Just (printf "Failed to get mimetype of %s: %s (exit code %d)"
                              package err code)
             Right stdout -> let mimeType = head (lines stdout) in
                             if mimeType `elem` packageMimeTypes then
                                 Nothing
                             else
                                 Just (printf "Invalid mimetype of %s: %s"
                                              package mimeType)

readPackage :: String -> IO (Either String Package)
readPackage package = do
  contents <- BS.readFile package
  mimeType <- verifyMimeType package
  case mimeType of
    Just errorMessage -> return (Left errorMessage)
    Nothing           -> return (Right Package { packageFileName = package
                                               , packageContents = contents})

-- Arguments handling

exitFailure :: String -> IO ()
exitFailure msg = IO.hPutStrLn IO.stderr msg >> exitWith (ExitFailure 1)

data Arguments = Arguments { argUsername :: String
                           , argPackageFile :: String}
               deriving (Show, Data, Typeable)

arguments :: IO Arguments
arguments = do
  programName <- getProgName
  return $ Arguments { argUsername = def &= argPos 0 &= typ "USERNAME"
                     , argPackageFile = def &= argPos 1 &= typ "PACKAGE" }
             &= summary (printf "%s %s" programName appVersion)
             &= help "Upload a PACKAGE to Marmalade."
             &= details ["Copyright (C) 2014 Sebastian Wiesner"
                        ,"Distributed under the terms of the MIT/X11 license."]
             &= program programName

main :: IO ()
main = do
  args <- arguments >>= cmdArgs
  result <- readPackage (argPackageFile args)
  case result of
    Left errorMessage -> exitFailure errorMessage
    Right package ->
        withManager $ \m -> doUpload m (Username (argUsername args)) package

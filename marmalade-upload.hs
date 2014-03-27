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
import Control.Monad (liftM,mzero)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.List (intersperse)
import Data.Foldable (mapM_)
import Data.Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Data.Conduit (ResourceT)
import Text.Printf (printf)
import System.IO.Error (ioError,userError)
import System.IO (hPutStrLn,hFlush
                 ,hGetEcho,hSetEcho
                 ,stdin,stdout,stderr)
import System.Environment (getProgName)
import System.Process (readProcessWithExitCode
                      ,createProcess,waitForProcess,proc)
import System.Exit (ExitCode(ExitSuccess,ExitFailure),exitWith)
import System.Console.CmdArgs hiding (args)
import Network.HTTP.Conduit
import Network.HTTP.Types.Header (hUserAgent)

data Arguments = Arguments { username :: String
                           , packageFile :: String}
               deriving (Show, Data, Typeable)

data Package = Package { packageFileName :: String
                       , packageContents :: BS.ByteString }

newtype Username = Username String deriving (Show, Eq)
newtype Token = Token String deriving (Show, Eq)

instance FromJSON Token where
    parseJSON (Object o) = Token <$> (o .: "token")
    parseJSON _          = mzero

service :: String
service = "lunaryorn/marmalade-upload"

packageMimeTypes :: [String]
packageMimeTypes = ["application/x-tar", "text/x-lisp"]

marmaladeURL :: String
marmaladeURL = "http://marmalade-repo.org"

withEcho :: Bool -> IO a -> IO a
withEcho echo action = bracket (hGetEcho stdin)
                       (hSetEcho stdin)
                       (const $ hSetEcho stdin echo >> action)

askPassword :: String -> IO String
askPassword prompt = do
  putStr prompt
  hFlush stdout
  password <- withEcho False getLine
  putChar '\n'
  return password

callProcess :: String -> [String] -> IO ()
callProcess executable args = do
  (_, _, _, handle) <- createProcess (proc executable args)
  exitCode <- waitForProcess handle
  case exitCode of
    ExitSuccess -> return ()
    ExitFailure code ->
        let cmd = executable ++ " " ++ concat (intersperse " " args) in
        ioError (userError (printf "%s (exit code %d)" cmd code))

checkOutput :: String -> [String] -> IO (Either (Int, String) String)
checkOutput executable args = do
  output <- readProcessWithExitCode executable args []
  return $ case output of
             (ExitSuccess, stdout, _)      -> Right stdout
             (ExitFailure code, _, stderr) -> Left (code, stderr)

getToken :: Username -> IO (Maybe Token)
getToken (Username username) = do
    output <- checkOutput "security" ["find-generic-password", "-w"
                                     ,"-a", username
                                     ,"-s", service]
    return $ case output of
               Left _ -> Nothing -- The item didn't exist
               Right stdout -> Just (Token (head (lines stdout)))

setToken :: Username -> Token -> IO ()
setToken (Username username) (Token token) =
    callProcess "security" ["add-generic-password"
                           ,"-a", username
                           ,"-s", service
                           ,"-w", token
                           ,"-U"
                           ,"-l", "Marmalade access token"]

makeRequest :: String -> ResourceT IO Request
makeRequest endpoint = do
  initReq <- parseUrl (marmaladeURL ++ endpoint)
  return initReq { requestHeaders = [(hUserAgent, UTF8.fromString service)] }

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

readPackage :: String -> IO (Either String BS.ByteString)
readPackage package = do
  contents <- BS.readFile package
  mimeType <- verifyMimeType package
  case mimeType of
    Just errorMessage -> return (Left errorMessage)
    Nothing           -> return (Right contents)

exitFailure :: String -> IO ()
exitFailure msg = hPutStrLn stderr msg >> exitWith (ExitFailure 1)

arguments :: IO Arguments
arguments = do
  programName <- getProgName
  return $ Arguments { username = def &= argPos 0 &= typ "USERNAME"
                     , packageFile = def &= argPos 1 &= typ "PACKAGE" }
             &= summary (printf "%s 0.1" programName)
             &= help "Upload a PACKAGE to Marmalade."
             &= details ["Copyright (C) 2014 Sebastian Wiesner"
                        ,"Distributed under the terms of the MIT/X11 license."]
             &= program programName

main :: IO ()
main = do
  args <- arguments >>= cmdArgs
  result <- readPackage (packageFile args)
  case result of
    Left errorMessage -> exitFailure errorMessage
    Right contents -> let package = Package { packageFileName = packageFile args
                                            , packageContents = contents} in
                      withManager $ \m ->
                          doUpload m (Username (username args)) package

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

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiParamTypeClasses #-}

import qualified Data.Aeson as JSON
import qualified Data.ByteString.UTF8 as UTF8
import qualified System.Directory as Dir
import qualified System.Environment as Env
import qualified System.Info as SI
import qualified System.IO as IO
import qualified Network as N
import qualified Network.HTTP.Client as C
import qualified System.Console.CmdArgs as Args

import Control.Applicative ((<$>))
import Control.Exception (bracket)
import Control.Failure (Failure(..))
import Control.Monad (liftM,mzero,void,unless,when)
import Control.Monad.Error (ErrorT,MonadError,Error(..),runErrorT,throwError)
import Control.Monad.IO.Class (MonadIO,liftIO)
import Control.Monad.State (StateT,MonadState,evalStateT,get,gets,put)
import Data.Aeson (FromJSON,Value(Object),(.:))
import Data.ByteString.Lazy (ByteString)
import Network.HTTP.Client (Manager,HttpException,Request,Response)
import Network.HTTP.Client.MultipartFormData
import Network.HTTP.Types.Header (hUserAgent)
import Network.HTTP.Types.Status (Status(statusCode,statusMessage))
import System.Console.CmdArgs (Data,Typeable,(&=),cmdArgs)
import System.Exit (ExitCode(ExitSuccess,ExitFailure),exitWith)
import System.IO.Error (tryIOError)
import System.Process (readProcessWithExitCode,callProcess)
import Text.Printf (printf)

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
tokenProvider = case SI.os of
                  "darwin" -> return (getTokenDarwin, setTokenDarwin)
                  "linux" -> do
                             desktop <- Env.getEnv "XDG_CURRENT_DESKTOP"
                             return $ case desktop of
                               "KDE" -> (getTokenKDE, setTokenKDE)
                               _ -> dummy
                  _ -> return dummy
  where
    dummy = (\_ -> return Nothing, \_ _ -> return ())

getToken :: Username -> IO (Maybe Token)
getToken username = do
  (getT, _) <- tokenProvider
  getT username

setToken :: Username -> Token -> IO ()
setToken username token = do
  (_, setT) <- tokenProvider
  setT username token

-- Marmalade access

newtype Username = Username String deriving (Show, Eq)
newtype Token = Token String deriving (Show, Eq)

instance FromJSON Token where
  parseJSON (Object o) = Token <$> (o .: "token")
  parseJSON _          = mzero

data MarmaladeError = IOError IOError
                    | HttpException HttpException
                    | InvalidResponseStatus Status (Maybe String)
                    | BadRequest (Maybe String)
                    | InvalidPackage FilePath String
                    | InvalidJSON ByteString
                    | GenericError String
                    | UnknownError

instance Show MarmaladeError where
  show (IOError e) = show e
  show (HttpException e) = "HTTP Error: " ++ show e
  show (InvalidResponseStatus status (Just message)) =
    printf "Invalid response status: %s (%s)" msgString message
    where msgString = UTF8.toString (statusMessage status)
  show (InvalidResponseStatus status Nothing) =
    printf "Invalid response status: %s" msgString
    where msgString = UTF8.toString (statusMessage status)
  show (BadRequest (Just message)) = "Bad Request: " ++ message
  show (BadRequest Nothing) = "Bad Request"
  show (InvalidPackage f m) = printf "%s: invalid package: %s" f m
  show (InvalidJSON s) = "Invalid JSON response: " ++ (show s)
  show (GenericError m) = "Unknown error: " ++ m
  show UnknownError = "Unknown error"

instance Error MarmaladeError where
  noMsg = UnknownError
  strMsg message = GenericError message

guard :: (MonadIO m, MonadError MarmaladeError m) => IO b -> m b
guard action = do
  result <- liftIO $ tryIOError action
  case result of
    Left e -> throwError (IOError e)
    Right r -> return r

data Auth = BasicAuth Username (Marmalade String)
          | TokenAuth Username Token

data MarmaladeState = MarmaladeState { marmaladeAuth :: Auth
                                     , marmaladeLoggedIn :: Bool
                                     , marmaladeManager :: Manager }

newtype Marmalade a =
  Marmalade { runM :: ErrorT MarmaladeError (StateT MarmaladeState IO) a }
  deriving (Monad,MonadIO,Functor
           ,MonadState MarmaladeState
           ,MonadError MarmaladeError)

instance Failure HttpException Marmalade where
  failure e = throwError (HttpException e)

runMarmalade :: Auth -> Manager -> Marmalade a -> IO (Either MarmaladeError a)
runMarmalade auth manager m = evalStateT (runErrorT (runM m)) state
  where state = MarmaladeState { marmaladeAuth = auth
                               , marmaladeLoggedIn = False
                               , marmaladeManager = manager}

newtype Message = Message { messageContents :: String }

instance FromJSON Message where
  parseJSON (Object o) = Message <$> (o .: "message")
  parseJSON _          = mzero

newtype Upload = Upload { uploadMessage :: String }

instance FromJSON Upload where
  parseJSON (Object o) = Upload <$> (o .: "message")
  parseJSON _          = mzero

marmaladeURL :: String
marmaladeURL = "http://marmalade-repo.org"

makeRequest :: String -> Marmalade Request
makeRequest endpoint = do
  initReq <- C.parseUrl (marmaladeURL ++ endpoint)
  return initReq { C.requestHeaders = [(hUserAgent, UTF8.fromString appUserAgent)]
                 -- We keep every bad status, because we handle these later
                 , C.checkStatus = \_ _ _ -> Nothing
                 }

parseResponse :: FromJSON c => Response ByteString -> Marmalade c
parseResponse response =
  case statusCode status of
    200 -> case JSON.decode body of
      Just o  -> return o
      Nothing -> throwError (InvalidJSON body)
    400 -> throwError (BadRequest message)
    _ -> throwError (InvalidResponseStatus status message)
  where body = C.responseBody response
        status = C.responseStatus response
        message = fmap messageContents (JSON.decode body)

-- Package handling

packageMimeTypes :: [String]
packageMimeTypes = ["application/x-tar", "text/x-lisp"]

login :: Marmalade (Username, Token)
login = do
  state <- get
  case marmaladeAuth state of
    BasicAuth username getPassword -> do
      token <- doLogin username getPassword
      put state { marmaladeLoggedIn = True
                , marmaladeAuth = TokenAuth username token }
      return (username, token)
    TokenAuth username token -> return (username, token)
  where doLogin (Username username) getPassword = do
          manager <- gets marmaladeManager
          password <- getPassword
          request <- liftM (C.urlEncodedBody [("name", UTF8.fromString username)
                                             ,("password", UTF8.fromString password)])
                     (makeRequest "/v1/users/login")
          response <- guard $ C.httpLbs request manager
          parseResponse response

verifyPackage :: String -> Marmalade ()
verifyPackage packageFile = do
  -- Force early failure if the package doesn't exist
  guard $ void $ Dir.getPermissions packageFile
  output <- guard $ checkOutput "file" ["--brief" ,"--mime-type", packageFile]
  case output of
    Left (code, err) -> throwError $
                        InvalidPackage packageFile
                        (printf "failed to get mimetype: %s (exit code %d)" err code)
    Right stdout ->
      let mimeType = head (lines stdout) in
      unless (mimeType `elem` packageMimeTypes)
      (throwError (InvalidPackage packageFile (printf "invalid mimetype %s" mimeType)))

uploadPackage :: FilePath -> Marmalade Upload
uploadPackage packageFile = do
  verifyPackage packageFile
  (Username username, Token token) <- login
  manager <- gets marmaladeManager
  request <- makeRequest "/v1/packages" >>=
             guard.formDataBody [partBS "name" (UTF8.fromString username)
                                ,partBS "token" (UTF8.fromString token)
                                ,partFileSource "package" packageFile]
  response <- guard $ C.httpLbs request manager
  parseResponse response

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
  result <- withManager' $ \m ->
    runMarmalade auth m $ do
      (username, token) <- login
      upload <- uploadPackage (argPackageFile args)
      isLoggedIn <- gets marmaladeLoggedIn
      when isLoggedIn (guard $ setToken username token)
      guard $ putStrLn (uploadMessage upload)
  case result of
    Left e -> exitFailure $ show e
    _ -> return ()
  where withManager' = N.withSocketsDo.C.withManager C.defaultManagerSettings

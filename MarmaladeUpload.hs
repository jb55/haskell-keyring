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

import qualified System.Keyring as K
import Web.Marmalade

import qualified System.Environment as Env
import qualified System.IO as IO
import qualified System.Console.CmdArgs as Args

import Control.Exception (bracket)
import Control.Monad (when)
import System.Console.CmdArgs (Data,Typeable,(&=),cmdArgs)
import System.Exit (ExitCode(ExitFailure),exitWith)
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

-- Authentication

askMarmaladePassword :: String -> Marmalade String
askMarmaladePassword username = do
  guard $ askPassword (printf "Marmalade password for %s (never stored): " username)

getAuth :: String -> IO Auth
getAuth username = do
  result <- K.getPassword (K.Service appService) (K.Username username)
  return $ case result of
    Just (K.Password token) -> (TokenAuth (Username username) (Token token))
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
    ((Username username), (Token token)) <- login
    upload <- uploadPackage (argPackageFile args)
    when mustSaveToken $
      guard (K.setPassword
             (K.Service appService)
             (K.Username username)
             (K.Password token))
    guard $ putStrLn (uploadMessage upload)
  case result of
    Left e -> exitFailure $ show e
    _ -> return ()

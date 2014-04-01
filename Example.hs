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

module Main where

import System.Keyring (Service(..),Username(..),Password(..)
                      ,getPassword,setPassword
                      ,KeyringError)

import Control.Exception (catch)
import Control.Monad (liftM)
import Data.Version (showVersion)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, hPutStr, hFlush, stderr, stdout)
import Text.Printf (printf)

import Paths_keyring (version)

ask :: String -> IO String
ask prompt = do
  hPutStr stdout prompt
  hFlush stdout
  getLine

service :: Service
service = Service "haskell-keyring-example"

handleKeyringError :: KeyringError -> IO ()
handleKeyringError exc =
  hPutStrLn stderr (show exc) >> exitFailure

roundTrip :: Username -> IO ()
roundTrip username = do
   password <- ask "A password (VISIBLE): "
   setPassword service username (Password password)
   result <- getPassword service username
   case result of
     (Just (Password storedPassword)) -> do
       let matching = if password == storedPassword then "ok" else "MISMATCH"
       printf "Password in keyring: %s (%s)\n" storedPassword matching
     Nothing -> hPutStrLn stderr "Error: Password NOT saved!" >> exitFailure

tryGetPassword :: IO ()
tryGetPassword = do
  username <- liftM Username (ask "A username: ")
  password <- getPassword service username
  case password of
    (Just (Password pw)) -> putStr "Your Password: " >> putStrLn pw
    Nothing -> putStrLn "No password in keyring" >> roundTrip username

showVersionInfo :: IO ()
showVersionInfo = printf "Keyring %s\n" (showVersion version)

main :: IO ()
main = do
  showVersionInfo
  catch tryGetPassword handleKeyringError

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
-- Install these with: cabal install cmdargs

{-# LANGUAGE DeriveDataTypeable #-}

import qualified Data.ByteString as BS
import Text.Printf (printf)
import System.IO (hPutStrLn,stderr)
import System.Environment (getProgName)
import System.Process (readProcessWithExitCode)
import System.Exit (ExitCode(ExitSuccess,ExitFailure),exitWith)
import System.Console.CmdArgs hiding (args)

data Arguments = Arguments { username :: String
                           , packageFile :: String}
               deriving (Show, Data, Typeable)

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

packageMimeTypes :: [String]
packageMimeTypes = ["application/x-tar", "text/x-lisp"]

verifyMimeType :: String -> IO (Maybe String)
verifyMimeType package = do
    (exitcode, stdout, stderr) <- readProcessWithExitCode "file"
                                ["--brief" ,"--mime-type", package] []
    case exitcode of
      ExitFailure code -> return (Just (printf "Failed to get mimetype of %s: %s (exit code %d)"
                                               package stderr code))
      ExitSuccess ->let mimeType = head (lines stdout) in
                    return $ if mimeType `elem` packageMimeTypes then
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

main :: IO ()
main = do
  args <- arguments >>= cmdArgs
  result <- readPackage (packageFile args)
  case result of
    Left errorMessage -> exitFailure errorMessage
    Right contents -> print contents

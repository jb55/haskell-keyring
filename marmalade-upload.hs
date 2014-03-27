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
import System.Console.CmdArgs
import System.Directory (doesFileExist)
import System.Process (readProcessWithExitCode)
import System.Exit (ExitCode(ExitSuccess,ExitFailure))

data Arguments = Arguments { username :: String
                           , packageFile :: String}
               deriving (Show, Data, Typeable)

arguments = Arguments { username = def
                                   &= typ "USERNAME"
                                   &= argPos 0
                      , packageFile = def
                                      &= typ "PACKAGE"
                                      &= argPos 1
                      }
            &= summary "marmalade-upload 0.1"
            &= help "Upload a PACKAGE to Marmalade."
            &= details ["Copyright (C) 2014 Sebastian Wiesner"
                       ,"Distributed under the terms of the MIT/X11 license."]
            &= program "marmalade-upload"

packageMimeTypes :: [String]
packageMimeTypes = ["application/x-tar", "text/x-lisp"]

readPackage :: String -> IO (Either String BS.ByteString)
readPackage package = do
  contents <- BS.readFile package
  (exitcode, stdout, stderr) <- readProcessWithExitCode "file"
                                ["--brief" ,"--mime-type"] []
  case exitcode of
    ExitSuccess -> let mimeType = head (lines stdout) in
                   if mimeType `elem` packageMimeTypes then
                       return (Right contents)
                   else
                       return (Left (printf "Invalid mimetype of %s: %s"
                                            package mimeType))
    ExitFailure code -> return (Left (printf "Failed to get mimetype of %s: %s (exit code %d)"
                                             package stderr code))
  return $ Right contents
  -- if not exists then Just package ++ "does not exist".
  -- (exitcode, stdout, _)

main :: IO ()
main = do
  args <- cmdArgs arguments
  contents <- readPackage (packageFile args)
  print contents

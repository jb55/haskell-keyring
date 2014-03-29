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

-- |Access to the OS X Keychain
module System.Keyring.Darwin (setPassword,getPassword) where

import System.Keyring.Types

import System.Exit (ExitCode(ExitSuccess))
import System.Process (readProcessWithExitCode,callProcess)

-- |@'setPassword' service username password@ stores a @password@ for a given
-- @username@ and @service@.
setPassword :: Service -> Username -> Password -> IO ()
setPassword (Service service) (Username username) (Password password) =
   callProcess "security" ["add-generic-password"
                          ,"-a", username
                          ,"-s", service
                          ,"-w", password
                          ,"-U"]

-- |@'getPassword' service username@ gets password for a given @username@ and
-- @service@.  If the password was not found, return 'Nothing' instead.
getPassword :: Service -> Username -> IO (Maybe Password)
getPassword (Service service) (Username username) = do
  output <- readProcessWithExitCode "security" ["find-generic-password", "-w"
                                               ,"-a", username
                                               ,"-s", service] []
  return $ case output of
    (ExitSuccess, stdout, _) -> Just (Password (head (lines stdout)))
    _ -> Nothing

=================
 haskell-keyring
=================

.. |hackage| image:: https://img.shields.io/hackage/v/keyring.svg?dummy
             :target: https://hackage.haskell.org/package/keyring

.. |license| image:: https://img.shields.io/badge/license-MIT-green.svg?dummy
             :target: https://github.com/lunaryorn/haskell-keyring/blob/master/LICENSE

.. default-role:: literal

|hackage| |license|

Haskell library to access the system's keyring to securely store passwords.

Supported keyring backends:

- Keychain on OS X
- KWallet on KDE

The library automatically chooses the appropriate backend for the current
system and environment.

Installation
============

From Hackage_:

.. code-block:: console

   $ cabal install keyring

.. _Hackage: http://hackage.haskell.org/package/keyring

Usage
=====

See `Example.hs`_ for a complete example.

.. _Example.hs: https://github.com/lunaryorn/haskell-keyring/blob/master/Example.hs

Getting passwords
-----------------

.. code-block:: haskell

   import System.Keyring

   main = do
     password <- getPassword (Service "my-application")
                             (Username "Joe")
     case password of
       (Just (Password pw)) ->
         putStrLn ("Your password is " ++ pw)
       Nothing ->
         putStrLn "No password found"

Setting passwords
-----------------

.. code-block:: haskell

   import System.Keyring

   main = setPassword (Service "my-application")
                      (Username "Joe")
                      (Password "my-secret-password")

Support
=======

- `Issue tracker`_

Contribute
==========

- `Issue tracker`_
- Github_

.. _Issue Tracker: https://github.com/lunaryorn/haskell-keyring/issues
.. _Github: https://github.com/lunaryorn/haskell-keyring

Credits
=======

- Contributors_

.. _Contributors:
https://github.com/lunaryorn/haskell-keyring/graphs/contributors

License
=======

Copyright (c) 2014 Sebastian Wiesner <lunaryorn@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

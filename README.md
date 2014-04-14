haskell-keyring
===============

[![hackage][badge-hackage]][hackage]
[![license][badge-license]][license]
[![travis][badge-travis]][travis]

Haskell library to access the system's keyring to securely store passwords.

Supported keyring backends:

- Keychain on OS X
- KWallet on KDE

The library automatically chooses the appropriate backend for the current
system and environment.

Installation
------------

From [Hackage][]:

```console
$ cabal install keyring
```

Usage
-----

See [Example.hs][example] for a complete example.

### Getting passwords

```haskell
import System.Keyring

main = do
  password <- getPassword (Service "my-application")
                          (Username "Joe")
  case password of
    (Just (Password pw)) ->
      putStrLn ("Your password is " ++ pw)
    Nothing ->
    putStrLn "No password found"
```

### Setting passwords

```haskell
import System.Keyring

main = setPassword (Service "my-application")
                   (Username "Joe")
                   (Password "my-secret-password")
```

Support
-------

- [Issue tracker][issues]

Contribute
----------

- [Issue tracker][issues]
- [Github][]

Credits
-------

- [Contributors](https://github.com/lunaryorn/haskell-keyring/graphs/contributors)

License
-------

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

[badge-travis]: https://travis-ci.org/lunaryorn/haskell-keyring.svg?branch=master
[travis]: https://travis-ci.org/lunaryorn/haskell-keyring
[badge-hackage]: https://img.shields.io/hackage/v/keyring.svg?dummy
[hackage]: https://hackage.haskell.org/package/keyring
[badge-license]: https://img.shields.io/badge/license-MIT-green.svg?dummy
[license]: https://github.com/lunaryorn/haskell-keyring/blob/master/LICENSE
[example]: https://github.com/lunaryorn/haskell-keyring/blob/master/Example.hs
[issues]: https://github.com/lunaryorn/haskell-keyring/issues
[Github]: https://github.com/lunaryorn/haskell-keyring

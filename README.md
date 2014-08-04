[![Build Status](https://travis-ci.org/alephcloud/hs-aws-general.svg?branch=master)](https://travis-ci.org/alephcloud/hs-aws-general)


Haskell Bindings for Amazon AWS General API
===========================================

*API Version 0.1*

[Amazon AWS General API Reference](http://docs.aws.amazon.com/general/latest/gr/)

Installation
============

Assuming that the Haskell compiler *GHC* and the Haskell build tool *cabal* is
already installed run the following command from the shell:

~~~{.sh}
cabal install --enable-tests
~~~

Running Tests
=============

~~~{.sh}
cabal test
~~~

Normalization of the date header breaks the AWS test suite, since the tests in
that test suite use an invalid date.

Date normalization is enabled by default but can be turned of via the cabal
(compiletime) flag `normalize-signature-v4-date`. When date normalization is
enabled the official AWS Signature V4 test-suite is skipped excluded from the
tests. In order to include this test-suite run the following shell commands:

~~~{.sh}
cabal configure --enable-tests -f-normalize-signature-v4-date
cabal test
~~~


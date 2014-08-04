{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: Main
-- Copyright: Copyright © 2014 AlephCloud Systems, Inc.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@alephcloud.com>
-- Stability: experimental

-- -------------------------------------------------------------------------- --
-- Main

import Test.Tasty

import qualified General as General
import qualified SignatureV4 as SigV4

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "AWS Tests"
    [ SigV4.tests
    , General.tests
    ]


{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module: General
-- Copyright: Copyright © 2014 AlephCloud Systems, Inc.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@alephcloud.com>
-- Stability: experimental
--
-- Unit tests for "Aws.General"
--
module General
( tests

-- * Test properties
, prop_textRoundtrip
, prop_textRoundtrips
) where

import Aws.General

import Test.Tasty
import Test.Tasty.QuickCheck

tests :: TestTree
tests = testGroup "AWS General"
    [ prop_textRoundtrips
    ]

-- -------------------------------------------------------------------------- --
-- Test properties

prop_textRoundtrip :: forall a . (Eq a, AwsType a) => a -> Bool
prop_textRoundtrip a = either (const False) (\(b :: a) -> a == b) $
    fromText . toText $ a

prop_textRoundtrips :: TestTree
prop_textRoundtrips = testGroup "Text encoding roundtrips"
    [ testProperty "Text roundtrip for GeneralVersion" (prop_textRoundtrip :: GeneralVersion -> Bool)
    , testProperty "Text roundtrip for SignatureVersion" (prop_textRoundtrip :: SignatureVersion -> Bool)
    , testProperty "Text roundtrip for SignatureMethod" (prop_textRoundtrip :: SignatureMethod -> Bool)
    , testProperty "Text roundtrip for Region" (prop_textRoundtrip :: Region -> Bool)
    , testProperty "Text roundtrip for AccountId" (prop_textRoundtrip :: AccountId -> Bool)
    , testProperty "Text roundtrip for CanonicalUserId" (prop_textRoundtrip :: CanonicalUserId -> Bool)
    , testProperty "Text roundtrip for ServiceNamespace" (prop_textRoundtrip :: ServiceNamespace -> Bool)
    , testProperty "Text roundtrip for Arn" (prop_textRoundtrip :: Arn -> Bool)
    ]

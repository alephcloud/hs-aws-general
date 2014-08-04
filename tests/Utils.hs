{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE GADTs #-}

-- |
-- Module: Utils
-- Copyright: Copyright © 2014 AlephCloud Systems, Inc.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@alephcloud.com>
-- Stability: experimental
--
-- Utils for Tests for Haskell AWS bindints
--
module Utils
(
-- * Parameters
  testRegion
, testDataPrefix

-- * General Utils
, sshow
, tryT
, retryT
, testData

, evalTestT
, evalTestTM
, eitherTOnceTest0
, eitherTOnceTest1
, eitherTOnceTest2

-- * Generic Tests
, test_jsonRoundtrip
, prop_jsonRoundtrip
) where

import Aws
import Aws.General

import Control.Concurrent (threadDelay)
import Control.Error
import Control.Exception
import Control.Monad
import Control.Monad.Identity
import Control.Monad.IO.Class

import Data.Aeson (FromJSON, ToJSON, encode, eitherDecode)
import qualified Data.ByteString as B
import qualified Data.List as L
import Data.Monoid
import Data.Proxy
import Data.String
import qualified Data.Text as T
import Data.Typeable

import Test.QuickCheck.Property
import Test.QuickCheck.Monadic
import Test.Tasty
import Test.Tasty.QuickCheck

import System.IO
import System.Exit
import System.Environment

-- -------------------------------------------------------------------------- --
-- Static Test parameters
--
-- TODO make these configurable

testRegion :: Region
testRegion = UsWest2

-- | This prefix is used for the IDs and names of all entities that are
-- created in the AWS account.
--
testDataPrefix :: IsString a => a
testDataPrefix = "__TEST_AWSHASKELLBINDINGS__"

-- -------------------------------------------------------------------------- --
-- General Utils

tryT :: MonadIO m => IO a -> EitherT T.Text m a
tryT = fmapLT (T.pack . show) . syncIO

testData :: (IsString a, Monoid a) => a -> a
testData a = testDataPrefix <> a

retryT :: MonadIO m => Int -> EitherT T.Text m a -> EitherT T.Text m a
retryT i f = go 1
  where
    go x
        | x >= i = fmapLT (\e -> "error after " <> sshow x <> " retries: " <> e) f
        | otherwise = f `catchT` \_ -> do
            liftIO $ threadDelay (1000000 * min 60 (2^(x-1)))
            go (succ x)

sshow :: (Show a, IsString b) => a -> b
sshow = fromString . show

evalTestTM
    :: Functor f
    => String -- ^ test name
    -> f (EitherT T.Text IO a) -- ^ test
    -> f (IO Bool)
evalTestTM name = fmap $
    runEitherT >=> \r -> case r of
        Left e -> do
            hPutStrLn stderr $ "failed to run stream test \"" <> name <> "\": " <> show e
            return False
        Right _ -> return True

evalTestT
    :: String -- ^ test name
    -> EitherT T.Text IO a -- ^ test
    -> IO Bool
evalTestT name = runIdentity . evalTestTM name . Identity

eitherTOnceTest0
    :: String -- ^ test name
    -> EitherT T.Text IO a -- ^ test
    -> TestTree
eitherTOnceTest0 name = testProperty name . once . ioProperty . evalTestT name

eitherTOnceTest1
    :: (Arbitrary a, Show a)
    => String -- ^ test name
    -> (a -> EitherT T.Text IO b)
    -> TestTree
eitherTOnceTest1 name test = testProperty name . once $ monadicIO . liftIO
    . evalTestTM name test

eitherTOnceTest2
    :: (Arbitrary a, Show a, Arbitrary b, Show b)
    => String -- ^ test name
    -> (a -> b -> EitherT T.Text IO c)
    -> TestTree
eitherTOnceTest2 name test = testProperty name . once $ \a b -> monadicIO . liftIO
    $ (evalTestTM name $ uncurry test) (a, b)

-- -------------------------------------------------------------------------- --
-- Generic Tests

test_jsonRoundtrip
    :: forall a . (Eq a, Show a, FromJSON a, ToJSON a, Typeable a, Arbitrary a)
    => Proxy a
    -> TestTree
test_jsonRoundtrip proxy = testProperty msg (prop_jsonRoundtrip :: a -> Property)
  where
    msg = "JSON roundtrip for " <> show (typeRep proxy)

prop_jsonRoundtrip :: forall a . (Eq a, Show a, FromJSON a, ToJSON a) => a -> Property
prop_jsonRoundtrip a = either (const $ property False) (\(b :: [a]) -> [a] === b) $
    eitherDecode $ encode [a]


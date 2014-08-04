{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances #-}

-- |
-- Module: SignatureV4
-- Copyright: Copyright © 2014 AlephCloud Systems, Inc.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@alephcloud.com>
-- Stability: experimental
--
-- Unit tests for "Aws.SignatureV4"
--
module SignatureV4
( tests

-- * Test Properties
, prop_canonicalHeaders
, allTests

) where

import General (prop_textRoundtrip)

import Aws.Core
import Aws.General
import Aws.SignatureV4

import Control.Applicative
import Control.Error.Util
import Control.Error (initSafe)
import Control.Exception
import Control.Monad
import Control.Monad.Trans.Either
import Control.Monad.IO.Class

import qualified Data.Attoparsec.ByteString.Char8 as A8
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.CaseInsensitive as CI
import Data.Function (on)
import qualified Data.List as L
import Data.Maybe
import Data.Monoid
import Data.String
import qualified Data.Text.Encoding as T
import Data.Time.Clock (UTCTime)
import Data.Tagged

import qualified Network.HTTP.Types as HTTP

import qualified Test.QuickCheck as Q
import Test.QuickCheck.Instances ()

import qualified Text.Parser.Char as P
import qualified Text.Parser.Combinators as P

import System.Directory
import System.IO.Unsafe (unsafePerformIO)

import Test.Tasty.QuickCheck
import Test.Tasty
import Test.Tasty.Providers

tests :: TestTree
tests = testGroup "SignatureV4"
    $ quickCheckTests
    : if dateNormalizationEnabled then [] else [awsSignatureV4TestSuite]

-- -------------------------------------------------------------------------- --
-- QuickCheck Properties

quickCheckTests :: TestTree
quickCheckTests = testGroup "quick queck tests"
    [ testProperty "canonical headers" prop_canonicalHeaders
    , testProperty "text roundtrip for CredentialScope"
        (prop_textRoundtrip :: CredentialScope -> Bool)
    ]

instance Q.Arbitrary (CI.CI B.ByteString) where
    arbitrary = CI.mk . T.encodeUtf8 <$> Q.arbitrary

prop_canonicalHeaders :: HTTP.RequestHeaders -> Bool
prop_canonicalHeaders h = let x = canonicalHeaders h in x `seq` True

-- -------------------------------------------------------------------------- --
-- AWS Signature V4 Test Suite
--
-- <http://docs.aws.amazon.com/general/1.0/gr/samples/aws4_testsuite.zip>
--
-- TODO use machinery from tasty-golden to run these tests
--

instance IsTest (IO Bool) where
    run _ t _ = t >>= \x -> return $ if x
        then testPassed ""
        else testFailed ""
    testOptions = Tagged []

simpleIOTest :: String -> IO Bool -> TestTree
simpleIOTest = singleTest

--

awsSignatureV4TestSuite :: TestTree
awsSignatureV4TestSuite = simpleIOTest "AWS Signature V4 Test Suite" allTests

baseDir :: String
baseDir = "./tests/signature-v4/aws4_testsuite"

testFileBase :: String -> String
testFileBase name = baseDir <> "/" <> name

readFileNormalized :: String -> IO B8.ByteString
readFileNormalized f = B8.filter (/= '\r') <$> B8.readFile f

amz_credentialScope :: CredentialScope
amz_credentialScope = either error id
    $ fromText "20110909/us-east-1/host/aws4_request"

amz_credentialsIO :: IO SignatureV4Credentials
amz_credentialsIO = newCredentials "AKIDEXAMPLE" "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

amz_credentials :: SignatureV4Credentials
amz_credentials = unsafePerformIO $ amz_credentialsIO
{-# NOINLINE amz_credentials #-}

-- | Note that the input is an invalid date. The day 2011-09-09 was a
-- a Friday in the Gregorian calendar.
--
amz_testDateStr :: IsString a => a
amz_testDateStr = "Mon, 09 Sep 2011 23:36:00 GMT"

amz_testDate :: UTCTime
amz_testDate = fromMaybe (error "failed to parse test date")
    $ parseHttpDate amz_testDateStr

-- | Test Parameters
--
data TestRequest = TestRequest
    { testRequestMethod :: !HTTP.Method
    , testRequestPath :: !UriPath
    , testRequestQuery :: !UriQuery
    , testRequestHeaders :: !HTTP.RequestHeaders
    , testRequestPayload :: !B.ByteString
    }
    deriving (Show, Eq)

parseRequest :: forall m . (Monad m, P.CharParsing m) => m TestRequest
parseRequest = uncurry <$> (TestRequest <$> word)
        <*> parseTestUri
        <*> many parseTestHeader
        <*> (fromString <$> ((line :: m String) *> P.manyTill P.anyChar P.eof))
        P.<?> "TestRequest"

parseTestUri :: forall m . P.CharParsing m => m (UriPath, UriQuery)
parseTestUri = fmap HTTP.queryToQueryText . HTTP.decodePath . B8.pack
    <$> word <* (line :: m String)

parseTestHeader :: P.CharParsing m => m HTTP.Header
parseTestHeader = (,)
    <$> (fromString <$> P.manyTill P.anyChar (P.char ':'))
    <*> line

word :: (P.CharParsing m, IsString a) => m a
word = fromString <$> P.manyTill P.anyChar (some P.space) P.<?> "word"

line :: (P.CharParsing m, IsString a) => m a
line = fromString
    <$> P.manyTill P.anyChar (P.newline *> P.notFollowedBy (P.char ' '))
    P.<?> "line"

-- ** Test Methods

testCanonicalRequest
    :: String
    -> TestRequest
    -> EitherT String IO CanonicalRequest
testCanonicalRequest name r = do
    creq_ <- liftIO $ readFileNormalized f
    if creq == creq_
    then return result
    else left $ "test " <> name <> " failed to compute canonical request: "
        <> "\n  expected:" <> show creq_
        <> "\n  computed:" <> show creq
  where
    f = testFileBase name <> ".creq"
    result@(CanonicalRequest creq) = canonicalRequest
        (testRequestMethod r)
        (testRequestPath r)
        (testRequestQuery r)
        (testRequestHeaders r)
        (testRequestPayload r)

testStringToSign
    :: String
    -> TestRequest
    -> CanonicalRequest
    -> EitherT String IO StringToSign
testStringToSign name _req creq = do
    sts_ <- liftIO $ readFileNormalized f
    if sts == sts_
    then return result
    else left $ "test " <> name <> " failed compute string to sgin: "
        <> "\n  expected:" <> show sts_
        <> "\n  computed:" <> show sts
  where
    f = testFileBase name <> ".sts"
    result@(StringToSign sts)  = stringToSign
        amz_testDate
        amz_credentialScope
        creq

testSignature :: String -> TestRequest -> StringToSign -> EitherT String IO Signature
testSignature name _req str = do
    sig_ <- liftIO $ getSignature <$> readFileNormalized f
    if sig == sig_
    then return result
    else left $ "test " <> name <> " failed to compute signature: "
        <> "\n  expected:" <> show sig_
        <> "\n  computed:" <> show sig
  where
    f = testFileBase name <> ".authz"
    key = signingKey amz_credentials amz_credentialScope
    result@(Signature sig) = requestSignature key str
    getSignature = snd . B8.spanEnd (/= '=')

testAuthorization :: String -> TestRequest -> Signature -> EitherT String IO B8.ByteString
testAuthorization name req sig = do
    authz_ <- liftIO $ readFileNormalized f
    authz <- result
    if authz == authz_
    then return authz
    else left $ "test " <> name <> " failed to compute authorization info: "
        <> "\n  expected:" <> show authz_
        <> "\n  computed:" <> show authz
  where
    f = testFileBase name <> ".authz"
    result = failWith "authorization header is missing"
        . lookup "authorization"
        . authorizationInfoHeader
        $ authorizationInfo
            amz_credentials
            amz_credentialScope
            (signedHeaders $ testRequestHeaders req)
            amz_testDate
            sig

-- | Run a single Test
--
testMain :: String -> IO Bool
testMain name = do
    testRequest <- readFileNormalized reqFile >>= \x -> case A8.parseOnly parseRequest x of
        Left e -> error $ "failed to parse test request file " <> reqFile <> ": " <> e
        Right r -> return r
    eitherT (\e -> putStrLn e >> return False) (const $ return True) $ do
        creq <- testCanonicalRequest name testRequest
        sts <- testStringToSign name testRequest creq
        sig <- testSignature name testRequest sts
        _authz <- testAuthorization name testRequest sig
        return True
  where
    reqFile = testFileBase name <> ".req"

-- | Run all Tests
--
allTests :: IO Bool
allTests = do
    testFiles <- filter isNotBlackListed
        . filter (L.isSuffixOf ".req")
        . concat . filter checkGroup . group
        <$> getDirectoryContents baseDir
    let sigtests = map (\x -> L.take (L.length x - 4) x) testFiles
    results <- forM sigtests $ \n ->
        testMain n `catch` \(e :: IOError) -> do
            putStrLn $ "test " <> n <> " failed with: " <> show e
            return False
    return $ and results
  where
    -- the Amazon AWS SignatureV4 test-suite seems incomplete.
    -- In particular the files with the results for
    -- /get-header-value-multiline.req/ seem to be missing.
    testExtensions = ["req", "creq", "sreq", "authz", "sts"]
    checkGroup g = L.intersect testExtensions (map fext g) == testExtensions
    group = L.groupBy ((==) `on` fbase)
    fbase = initSafe . L.dropWhileEnd (/= '.')
    fext = takeEndWhile (/= '.')
    takeEndWhile f = reverse . takeWhile f  . reverse

    -- the test *post-vanilla-query-nonunreserved* of the
    -- Amazon AWS SignatureV4 testsuite uses an inconsistent request
    -- format that can not be represented with the URI query
    -- type of the *http-types* package. Also the given result
    -- itself seems suspicious. We skip this test

    testBlackList =
        [ "post-vanilla-query-nonunreserved"
        ]
    testName = takeEndWhile (/= '/') . fbase
    isNotBlackListed = not . flip elem testBlackList . testName


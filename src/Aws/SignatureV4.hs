{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE CPP #-}

-- |
-- Module: Aws.SignatureV4
-- Copyright: Copyright © 2014 AlephCloud Systems, Inc.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@alephcloud.com>
-- Stability: experimental
--
-- AWS Signature Version 4
--
-- /API Version: 1.0/
--
-- <http://docs.aws.amazon.com/general/1.0/gr/signature-version-4.html>
--
module Aws.SignatureV4
(

-- * AWS General API Version
  GeneralVersion(..)
, generalVersionToText
, parseGeneralVersion

-- * Signature Version
, signatureVersion

-- * AWS Credentials
, SignatureV4Credentials(..)
, newCredentials

-- $requesttypes

-- * Pure signing
, signPostRequest
, signGetRequest

-- * Signing With Cached Key
, signPostRequestIO
, signGetRequestIO

-- * Authorization Info
, AuthorizationInfo(..)
, authorizationInfo
, authorizationInfoQuery
, authorizationInfoHeader

-- * Internal

, dateNormalizationEnabled

-- ** Constants
, signingAlgorithm

-- ** Canoncial URI
, UriPath
, UriQuery
, normalizeUriPath
, normalizeUriQuery
, CanonicalUri(..)
, canonicalUri

-- ** Canonical Headers
, CanonicalHeaders(..)
, canonicalHeaders

-- ** SignedHeaders
, SignedHeaders
, signedHeaders

-- ** Canonical Request
, CanonicalRequest(..)
, canonicalRequest
, HashedCanonicalRequest
, hashedCanonicalRequest

-- ** Credenital Scope
, CredentialScope(..)
, credentialScopeToText

-- ** String to Sign
, StringToSign(..)
, stringToSign

-- ** Signing Key
, SigningKey(..)
, signingKey

-- * Signature
, Signature(..)

-- ** Low level signing function
, requestSignature
) where

-- import Aws.Core
import Aws.General

import Control.Applicative
import Control.Arrow hiding (left)
import Control.Monad.IO.Class

import Crypto.Hash

import Data.Byteable
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Blaze.ByteString.Builder as BB
import qualified Blaze.ByteString.Builder.Char8 as BB8
import qualified Data.ByteString.Base16 as B16
import Data.Char
import qualified Data.CaseInsensitive as CI
import Data.IORef
import qualified Data.List as L
import Data.Monoid
import Data.String
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Time.Clock (UTCTime, getCurrentTime, utctDay)
import Data.Time.Format (formatTime, parseTime)
import Data.Typeable

import qualified Test.QuickCheck as Q
import Test.QuickCheck.Instances ()

import qualified Text.Parser.Char as P
import qualified Text.Parser.Combinators as P

#if MIN_VERSION_time(1,5,0)
import Data.Time.Format
#else
import System.Locale
#endif

import qualified Network.HTTP.Types as HTTP

-- -------------------------------------------------------------------------- --
-- Constants

-- | We only support SHA256 since SHA1 has been deprecated
--
signingAlgorithm :: IsString a => a
signingAlgorithm = "AWS4-HMAC-SHA256"

signingHash :: B.ByteString -> B.ByteString
signingHash i = toBytes (hash i :: Digest SHA256)

signingHash16 :: B.ByteString -> B8.ByteString
signingHash16 = B16.encode . signingHash

signingHmac :: B.ByteString -> B.ByteString -> B.ByteString
signingHmac k i = toBytes (hmac k i :: HMAC SHA256)

-- -------------------------------------------------------------------------- --
-- Version

signatureVersion :: IsString a => a
signatureVersion = "4"

-- -------------------------------------------------------------------------- --
-- Signature V4 Credentials

type SigV4Key = ((B.ByteString,B.ByteString),(B.ByteString,B.ByteString))

-- | AWS access credentials.
--
-- This type is compatible with the 'Credential' type from the
-- <https://hackage.haskell.org/package/aws aws package>. You may
-- use the following function to get a 'SignatureV4Credential'
-- from a 'Credential':
--
-- > cred2credv4 :: Credential -> SignatureV4Credential
-- > #if MIN_VERSION_aws(0,9,2)
-- > cred2credv4 (Credential a b c _) = SignatureV4Credential a b c
-- > #else
-- > cred2credv4 (Credential a b c) = SignatureV4Credential a b c
-- > #endif
--
data SignatureV4Credentials = SignatureV4Credentials
    { sigV4AccessKeyId :: B.ByteString
    , sigV4SecretAccessKey :: B.ByteString
    , sigV4SigningKeys :: IORef [SigV4Key]
    -- ^ used internally for caching the singing key
    , sigV4SecurityToken :: Maybe B.ByteString
    }
    deriving (Typeable)

newCredentials
    :: (Functor m, MonadIO m)
    => B.ByteString -- ^ Access Key ID
    -> B.ByteString -- ^ Secret Access Key
    -> Maybe B.ByteString -- ^ Security Token
    -> m SignatureV4Credentials
newCredentials accessKeyId secretAccessKey securityToken = do
    signingKeysRef <- liftIO $ newIORef []
    return $ SignatureV4Credentials accessKeyId secretAccessKey signingKeysRef securityToken

-- -------------------------------------------------------------------------- --
-- Canonical URI

type UriPath = [T.Text]
type UriQuery = HTTP.QueryText

newtype CanonicalUri = CanonicalUri B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Compute canonical URI
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-create-canonical-request.html>
--
-- The input is assumed to be an absolute URI. If the first segment is @..@ it
-- is kept as is. Most likely such an URI is invalid.
--
canonicalUri
    :: UriPath
    -> UriQuery
    -> CanonicalUri
canonicalUri path query = CanonicalUri . BB.toByteString
    $ HTTP.encodePathSegments normalizedPath
    <> BB.copyByteString "\n"
    <> HTTP.renderQueryText False normalizedQuery
  where
    normalizedPath = case normalizeUriPath path of
        [] -> [""]
        a -> a
    normalizedQuery = L.sort
        . map (second $ maybe (Just "") Just)
        $ normalizeUriQuery query

-- | Normalize URI Path according to RFC 3986 (6.2.2)
--
normalizeUriPath :: UriPath -> UriPath
normalizeUriPath =
    -- normalize case and percent encoding
    HTTP.decodePathSegments . BB.toByteString . HTTP.encodePathSegments
    -- remove all "." segments
    -- remove all inner and trailing ".." segments (ignore leading ".." segments)
    . reverse . L.foldl' f []
  where
    f [] ".." = [".."]
    f (_:t) ".." = t
    f l "." = l
    f ("":t) a = a:t
    f l a = a:l

-- | Normalize URI Query according to RFC 3986 (6.2.2)
--
normalizeUriQuery :: UriQuery -> UriQuery
normalizeUriQuery =
    -- normalize case and percent encoding
    HTTP.parseQueryText . BB.toByteString . HTTP.renderQueryText False

-- -------------------------------------------------------------------------- --
-- Canonical Headers

newtype CanonicalHeaders = CanonicalHeaders B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Compute canonical HTTP headers
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-create-canonical-request.html>
--
-- It is assumed (and not checked) that the header values comform with the
-- definitions in RFC 2661. In particular non-comformant usage of quotation
-- characters may lead to invalid results.
--
canonicalHeaders :: HTTP.RequestHeaders -> CanonicalHeaders
canonicalHeaders = CanonicalHeaders
    . foldHeaders
    . L.sort -- Note this /must/ be a stable sorting algorithm!

    -- The following breaks the AWS test suite, since the tests in that
    -- test suite use an invalid date!
    --
#ifdef SIGN_V4_NORMALIZE_DATE
    . map canonicalDate
#endif
  where

#ifdef SIGN_V4_NORMALIZE_DATE
    canonicalDate :: HTTP.Header -> HTTP.Header
    canonicalDate ("date", d) = ("date", formatDate)
      where
        formatDate = case parseHttpDate (B8.unpack d) of
            Nothing -> d
            Just utc -> B8.pack $ fTime canonicalDateHeaderFormat utc
    canonicalDate a = a
#endif

    -- fold headers with the same name into a single HTTP header with
    -- comma separated values. Make all header names lower-case and
    -- terminate all headers by a new-line character.
    foldHeaders :: HTTP.RequestHeaders -> B8.ByteString
    foldHeaders [] = ""
    foldHeaders ((h0,v0):t) = BB.toByteString $ snd run <> bChar '\n'
      where
        run = L.foldl' f (h0, bBS (CI.foldedCase h0) <> bChar ':' <> trimWs v0) t
        f (ch, a) (h,v) = if ch == h
            then (h, a <> bChar ',' <> trimWs v)
            else (h, a <> bChar '\n' <> bBS (CI.foldedCase h) <> bChar ':' <> trimWs v)

    trimWs = (\(_,_,c) -> c)
        -- This strips all leading whitespace and collapses inner unquoted whitespace
        . B8.foldl' f (False, ' ', bBS "")
        -- This strips all trailing whitespace
        . fst . B8.spanEnd isSpace
      where
        -- escaping (we assume that we are withing quote but don't check!)
        f (s, '\\', b) x = (s, x, b <> bChar x)

        -- an unescaped quote toggles the quoting mode
        f (s, _, b) '"' = (not s, '"', b <> bChar '"')

        -- white space outside of quotation
        f (False, ' ', b) x
            | isSpace x = (False, ' ', b)
        f (False, _, b) x
            | isSpace x = (False, ' ', b <> bChar ' ')

        -- nothing special here
        f (s, _, b) x = (s, x, b <> bChar x)

    bChar = BB8.fromChar
    bBS = BB.copyByteString

#ifdef SIGN_V4_NORMALIZE_DATE
canonicalDateHeaderFormat :: String
canonicalDateHeaderFormat = "%a, %d %b %Y %H:%M:%S GMT"

-- | Parse HTTP-date according to section 3.3.1 of RFC 2616
--
-- the implementation is copie from the module "Aws.Core"
-- of the <https://hackage.haskell.org/package/aws aws package>.
--
parseHttpDate :: String -> Maybe UTCTime
parseHttpDate s =
        p "%a, %d %b %Y %H:%M:%S GMT" s -- rfc1123-date
    <|> p "%A, %d-%b-%y %H:%M:%S GMT" s -- rfc850-date
    <|> p "%a %b %_d %H:%M:%S %Y" s     -- asctime-date
    <|> p "%Y-%m-%dT%H:%M:%S%QZ" s      -- iso 8601
    <|> p "%Y-%m-%dT%H:%M:%S%Q%Z" s     -- iso 8601
  where
    p = parseTime defaultTimeLocale
#endif

-- | Normalization of the date header breaks the AWS test suite, since the
-- tests in that test suite use an invalid date.
--
-- Date normalization is enabled by default but can be turned of via the cabal
-- (compiletime) flag @normalize-signature-v4-date@.
--
dateNormalizationEnabled :: Bool
#ifdef SIGN_V4_NORMALIZE_DATE
dateNormalizationEnabled = True
#else
dateNormalizationEnabled = False
#endif

-- -------------------------------------------------------------------------- --
-- Signed Headers

newtype SignedHeaders = SignedHeaders B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Compute signed headers
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-create-canonical-request.html>
--
signedHeaders :: HTTP.RequestHeaders -> SignedHeaders
signedHeaders = SignedHeaders
    . B8.intercalate ";"
    . L.nub
    . L.sort
    . map (CI.foldedCase . fst)

-- -------------------------------------------------------------------------- --
-- Canonical Request

newtype CanonicalRequest = CanonicalRequest B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Create Canonical Request for AWS Signature Version 4
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-create-canonical-request.html>
--
-- This functions performs normalization of the URI and the Headers which is
-- expensive. We should consider providing an alternate version of this
-- function that bypasses these steps and simply assumes that the input is
-- already canonical.
--
canonicalRequest
    :: HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ canonical URI Path of request
    -> UriQuery -- ^ canonical URI Query of request
    -> HTTP.RequestHeaders -- ^ canonical request headers
    -> B.ByteString -- ^ Request payload
    -> CanonicalRequest
canonicalRequest method path query headers payload =
    CanonicalRequest $ B8.intercalate "\n"
        [ method
        , cUri
        , cHeaders
        , sHeaders
        , signingHash16 payload
        ]
  where
    CanonicalUri cUri = canonicalUri path query
    CanonicalHeaders cHeaders = canonicalHeaders headers
    SignedHeaders sHeaders = signedHeaders headers

-- The hash is stored hex encoded
--
newtype HashedCanonicalRequest = HashedCanonicalRequest B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

hashedCanonicalRequest :: CanonicalRequest -> HashedCanonicalRequest
hashedCanonicalRequest (CanonicalRequest r) = HashedCanonicalRequest
    $ signingHash16 r

-- -------------------------------------------------------------------------- --
-- Credential Scope

data CredentialScope = CredentialScope
    { credentialScopeDate :: !UTCTime
    , credentialScopeRegion :: !Region
    , credentialScopeService :: !ServiceNamespace
    }
    deriving (Show, Read, Typeable)

instance Eq CredentialScope where
    CredentialScope a0 b0 c0 == CredentialScope a1 b1 c1 =
        utctDay a0 == utctDay a1
        && b0 == b1
        && c0 == c1

credentialScopeToText :: (IsString a, Monoid a) => CredentialScope -> a
credentialScopeToText s =
    credentialScopeDateText s
    <> "/" <> toText (credentialScopeRegion s)
    <> "/" <> toText (credentialScopeService s)
    <> "/" <> terminationString

parseCredentialScope :: (Monad m, P.CharParsing m) => m CredentialScope
parseCredentialScope = CredentialScope
    <$> time
    <*> (P.char '/' *> parseRegion)
    <*> (P.char '/' *> parseServiceNamespace)
    <* (P.char '/' *> P.text terminationString)
  where
    time = do
        str <- P.count 8 P.digit
        case parseTime defaultTimeLocale credentialScopeDateFormat str of
            Nothing -> fail $ "failed to parse credential scope date: " <> str
            Just t -> return t

terminationString :: IsString a => a
terminationString = "aws4_request"

credentialScopeDateFormat :: IsString a => a
credentialScopeDateFormat = "%Y%m%d"

credentialScopeDateText :: IsString a => CredentialScope -> a
credentialScopeDateText s = fTime credentialScopeDateFormat (credentialScopeDate s)

instance AwsType CredentialScope where
    toText = credentialScopeToText
    parse = parseCredentialScope

instance Q.Arbitrary CredentialScope where
    arbitrary = CredentialScope
        <$> Q.arbitrary
        <*> Q.arbitrary
        <*> Q.arbitrary

-- -------------------------------------------------------------------------- --
-- String to Sign

newtype StringToSign = StringToSign B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Create the String to Sign for AWS Signature Version 4
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-create-string-to-sign.html>
--
stringToSign
    :: UTCTime -- ^ request date
    -> CredentialScope -- ^ credential scope for the request
    -> CanonicalRequest -- ^ canonical request
    -> StringToSign
stringToSign date credentialScope request = StringToSign $ B8.intercalate "\n"
    [ signingAlgorithm
    , fTime signingStringDateFormat date
    , T.encodeUtf8 $ credentialScopeToText credentialScope
    , hashedRequest
    ]
  where
    HashedCanonicalRequest hashedRequest = hashedCanonicalRequest request

signingStringDateFormat :: IsString a => a
signingStringDateFormat = "%Y%m%dT%H%M%SZ"

-- -------------------------------------------------------------------------- --
-- Derivation of Signing Key

-- | This key can be computed once and cached. It is valid for all requests
-- to the same service and the region till 00:00:00 UTC time.
--
newtype SigningKey = SigningKey B.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Derive the signing key
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-calculate-signature.html>
--
signingKey :: SignatureV4Credentials -> CredentialScope -> SigningKey
signingKey credentials s = SigningKey kSigning
  where
    kSecret = sigV4SecretAccessKey credentials
    kDate = signingHmac (signingKeyPrefix <> kSecret) dateStr
    kRegion = signingHmac kDate regionStr
    kService = signingHmac kRegion serviceStr
    kSigning = signingHmac kService terminationString

    dateStr = T.encodeUtf8 $ credentialScopeDateText s
    regionStr = T.encodeUtf8 . toText $ credentialScopeRegion s
    serviceStr = T.encodeUtf8 . toText $ credentialScopeService s

signingKeyPrefix :: IsString a => a
signingKeyPrefix = "AWS4"

-- -------------------------------------------------------------------------- --
-- Request Signature

newtype Signature = Signature B8.ByteString
    deriving (Show, Read, Eq, Ord, Typeable)

-- | Compute an AWS Signature Version 4
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-calculate-signature.html>
--
requestSignature
    :: SigningKey
    -> StringToSign
    -> Signature
requestSignature (SigningKey key) (StringToSign str) =
    Signature . B16.encode $ signingHmac key str

-- -------------------------------------------------------------------------- --
-- Authorization Info

authorizationCredential
    :: (IsString a, Monoid a)
    => SignatureV4Credentials
    -> CredentialScope
    -> a
authorizationCredential creds credScope =
    (fromString . B8.unpack . sigV4AccessKeyId) creds <> "/" <> toText credScope

data AuthorizationInfo = AuthorizationInfo
    { authzInfoAlgorithm :: !B8.ByteString
    , authzInfoCredential :: !B8.ByteString
    , authzInfoSignedHeaders :: !B8.ByteString
    , authzInfoDate :: !UTCTime
    , authzInfoSignature :: !B8.ByteString
    }

authorizationInfo
    :: SignatureV4Credentials
    -> CredentialScope
    -> SignedHeaders
    -> UTCTime
    -> Signature
    -> AuthorizationInfo
authorizationInfo creds credScope (SignedHeaders hdrs) date (Signature sig) = AuthorizationInfo
    { authzInfoAlgorithm = signingAlgorithm
    , authzInfoCredential = authorizationCredential creds credScope
    , authzInfoSignedHeaders = hdrs
    , authzInfoDate = date
    , authzInfoSignature = sig
    }

authorizationInfoQuery :: AuthorizationInfo -> UriQuery
authorizationInfoQuery authz =
    [ ("X-Amz-Signature", Just . T.decodeUtf8 $ authzInfoSignature authz)
    ]

authorizationInfoHeader
    :: AuthorizationInfo
    -> HTTP.RequestHeaders
authorizationInfoHeader authz = [ ("Authorization", authzInfo) ]
  where
    authzInfo = authzInfoAlgorithm authz
        <> " Credential=" <> authzInfoCredential authz
        <> ", SignedHeaders=" <> authzInfoSignedHeaders authz
        <> ", Signature=" <> authzInfoSignature authz

-- -------------------------------------------------------------------------- --
-- Signing Function

-- $requesttypes
-- = AWS Signature 4 Request Types
--
-- There are two types of version 4 signed requests for GET and for POST
-- requests
--
-- <http://docs.aws.amazon.com/general/1.0/gr/sigv4-signed-request-examples.html>
--
-- == Common Parameters
--
-- Both request types must include the following information in some way
--
-- <http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html>
--
-- * Host
-- * Action
-- * Date
-- * Authorization parameters:
--
--     * Algorithm
--     * Credential
--     * Signed headers
--     * signature
--
-- == POST Request
--
-- Computed by 'signPostRequest' or 'signPostRequestIO'.
--
-- Headers:
--
-- * @host@,
-- * @x-amz-date@ (or @date@),
-- * @authorization@ (containing all authorization parameters), and
-- * @content-type: application/x-www-form-urlencoded. charset=utf-8@.
--
-- The query parameters (including @Action@ and @Version@) are placed in the body.
--
-- == GET Request
--
-- Computed with 'signGetRequest' or 'signGetRequestIO'.
--
-- Headers:
--
-- * @host@
--
-- TODO why is this @content-type@ required?
--
-- Query:
--
-- * @Action@,
-- * @Version@,
-- * @X-Amz-Algorithm@,
-- * @X-Amz-Credential@,
-- * Authorization parameters:
--
--     * @X-Amz-Date@,
--     * @X-Amz-SignedHeaders@,
--     * @X-Amz-Signature@,
--     * @SignedHeaders@,
--     * @Signature@.
--
-- (NOTE that the AWS specification considers @X-Amz-Date@ an authorization parameter
-- only for URI requests. So for URI requests there are five authorization parameters
-- whereas otherwise there are just four.)
--
-- Somewhat surprisingly (and covered neither by the AWS Signature V4 test suite
-- nor by the AWS API reference) the canonical request includes all authorization
-- parameters except for the signature.
--
-- TODO: is it possible to do a POST with this style and place the query in the body?
--

-- | Compute an AWS Signature Version 4
--
-- This version computes the derivied signing key each time it is invoked
--
-- The request headers /must/ include the @host@ header.
-- The query /must/ include the @Action@ parameter.
--
signGetRequest
    :: SignatureV4Credentials -- ^ AWS credentials
    -> Region -- ^ request region
    -> ServiceNamespace -- ^ service of the request
    -> UTCTime -- ^ request time
    -> HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ URI Path of request
    -> UriQuery -- ^ URI Query of request
    -> HTTP.RequestHeaders -- ^ request headers
    -> B.ByteString -- ^ request payload
    -> Either String UriQuery
signGetRequest credentials region service date = signGetRequest_ key credentials region service date
  where
    key = signingKey credentials CredentialScope
        { credentialScopeDate = date
        , credentialScopeRegion = region
        , credentialScopeService = service
        }

signGetRequest_
    :: SigningKey
    -> SignatureV4Credentials -- ^ AWS credentials
    -> Region -- ^ request region
    -> ServiceNamespace -- ^ service of the request
    -> UTCTime -- ^ request time
    -> HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ URI Path of request
    -> UriQuery -- ^ URI Query of request
    -> HTTP.RequestHeaders -- ^ request headers
    -> B.ByteString -- ^ request payload
    -> Either String UriQuery
signGetRequest_ key credentials region service date method path query headers payload = do
    case lookup "host" headers of
        Nothing -> Left "Failed to sign request with Signature V4: host header is missing"
        Just _ -> return ()
    case lookup "Action" query of
        Nothing -> Left "Failed to sign request with Signature V4: Action parameter is missing"
        Just _ -> return ()
    return $ queryToSign <> authorizationInfoQuery authz
  where
    queryToSign = query <>
        [ ("X-Amz-Algorithm", Just signingAlgorithm)
        , ("X-Amz-Credential", Just $ authorizationCredential credentials credentialScope)
        , ("X-Amz-Date", Just $ fTime signingStringDateFormat date)
        , ("X-Amz-SignedHeaders", let SignedHeaders h = shdrs in Just (T.decodeUtf8 h))
        ]
    authz = authorizationInfo credentials credentialScope shdrs date sig
    sig = requestSignature key str
    shdrs = signedHeaders headers
    request = canonicalRequest method path queryToSign headers payload
    str = stringToSign date credentialScope request
    credentialScope = CredentialScope
        { credentialScopeDate = date
        , credentialScopeRegion = region
        , credentialScopeService = service
        }

-- | Compute an AWS Signature Version 4
--
-- This version computes the derivied signing key each time it is invoked
--
-- The request headers /must/ include the @host@ header.
-- The query /must/ include the @Action@ parameter.
--
-- The @x-amz-date@ header is generated by the code. A possibly existing
-- @x-amz-date@ header or @date@ header is replaced.
--
signPostRequest
    :: SignatureV4Credentials -- ^ AWS credentials
    -> Region -- ^ request region
    -> ServiceNamespace -- ^ service of the request
    -> UTCTime -- ^ request time
    -> HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ URI Path of request
    -> UriQuery -- ^ URI Query of request
    -> HTTP.RequestHeaders -- ^ request headers
    -> B.ByteString -- ^ request payload
    -> Either String HTTP.RequestHeaders
signPostRequest credentials region service date = signPostRequest_ key credentials region service date
  where
    key = signingKey credentials CredentialScope
        { credentialScopeDate = date
        , credentialScopeRegion = region
        , credentialScopeService = service
        }

signPostRequest_
    :: SigningKey
    -> SignatureV4Credentials -- ^ AWS credentials
    -> Region -- ^ request region
    -> ServiceNamespace -- ^ service of the request
    -> UTCTime -- ^ request time
    -> HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ URI Path of request
    -> UriQuery -- ^ URI Query of request
    -> HTTP.RequestHeaders -- ^ request headers
    -> B.ByteString -- ^ request payload
    -> Either String HTTP.RequestHeaders -- ^ the updated HTTP headers
signPostRequest_ key credentials region service date method path query headers payload = do
    case lookup "host" headers of
        Nothing -> Left "Failed to sign request with Signature V4: host header is missing"
        Just _ -> return ()

    -- In the post case can be in the body...
    -- case lookup "Action" query of
    --    Nothing -> Left "Failed to sign request with Signature V4: Action parameter is missing"
    --    Just _ -> return ()
    return $ headersWithDate <> authorizationInfoHeader authz

  where
    authz = authorizationInfo credentials credentialScope shdrs date sig
    sig = requestSignature key str
    shdrs = signedHeaders headersWithDate
    request = canonicalRequest method path query headersWithDate payload
    str = stringToSign date credentialScope request
    credentialScope = CredentialScope
        { credentialScopeDate = date
        , credentialScopeRegion = region
        , credentialScopeService = service
        }
    headersWithDate = ("x-amz-date", fTime signingStringDateFormat date)
        : filter (\x -> fst x /= "date" && fst x /= "x-amz-date") headers

-- -------------------------------------------------------------------------- --
-- Sign Request in IO

-- |
-- The request headers /must/ include the @host@ header.
-- The query /must/ include the @Action@ parameter.
--
signGetRequestIO
    :: SignatureV4Credentials -- ^ AWS credentials
    -> Region
    -> ServiceNamespace
    -> UTCTime
    -> HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ URI Path of request
    -> UriQuery -- ^ URI Query of request
    -> HTTP.RequestHeaders -- ^ request headers
    -> B.ByteString -- ^ request payload
    -> IO (Either String UriQuery)
signGetRequestIO credentials region service date method path query headers payload = do
    key <- getSigningKey credentials region service
    return $ signGetRequest_ key credentials region service date method path query headers payload

-- |
-- The request headers /must/ include the @host@ header.
-- The query /must/ include the @Action@ parameter.
--
-- The @x-amz-date@ header is generated by the code. A possibly existing
-- @x-amz-date@ header or @date@ header is replaced.
--
signPostRequestIO
    :: SignatureV4Credentials -- ^ AWS credentials
    -> Region
    -> ServiceNamespace
    -> UTCTime
    -> HTTP.Method -- ^ HTTP method of request
    -> UriPath -- ^ URI Path of request
    -> UriQuery -- ^ URI Query of request
    -> HTTP.RequestHeaders -- ^ request headers
    -> B.ByteString -- ^ request payload
    -> IO (Either String HTTP.RequestHeaders)
signPostRequestIO credentials region service date method path query headers payload = do
    key <- getSigningKey credentials region service
    return $ signPostRequest_ key credentials region service date method path query headers payload

-- | Get cached signing key
--
-- This should be improved:
--
-- 1. use an MVar instead of an IORef (for thread safety)
--
-- 2. use a better cache data structure (either a dense vector of MVars or
--    a hashmap.
--
-- 3. use more efficient value representations:
--
--    * Hashable instance for the index (or use a Int directly)
--    * represent dates as number of days or seconds (e.g. since epoche)
--
getSigningKey
    :: SignatureV4Credentials -- ^ AWS credentials
    -> Region
    -> ServiceNamespace
    -> IO SigningKey
getSigningKey credentials region service = do
    date <- getCurrentTime
    let dateStr = fTime credentialScopeDateFormat date

    k <- atomicModifyIORef' (sigV4SigningKeys credentials) $ \cache ->
        case L.lookup idx cache of
            Just (d,k) -> if d /= dateStr
                then newKey date dateStr cache
                else (cache,k)
            Nothing -> newKey date dateStr cache

    return $ SigningKey k
  where
    idx = ((T.encodeUtf8 . toText) region, (T.encodeUtf8 . toText) service)
    newKey date dateStr c =
        let SigningKey key = signingKey credentials CredentialScope
                { credentialScopeDate = date
                , credentialScopeRegion = region
                , credentialScopeService =  service
                }
            c_ = (idx, (dateStr,key)):c
        in key `seq` c_ `seq` (c_, key)

-- -------------------------------------------------------------------------- --
-- Utils

fTime :: IsString a => String -> UTCTime -> a
fTime format time = fromString $ formatTime defaultTimeLocale format time


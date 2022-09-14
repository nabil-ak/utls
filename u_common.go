// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
)

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.
const (
	// utlsExtensionPadding              uint16 = 21
	// utlsExtensionExtendedMasterSecret uint16 = 23 // https://tools.ietf.org/html/rfc7627

	// https://datatracker.ietf.org/doc/html/rfc8879#section-7.1
	// utlsExtensionCompressCertificate uint16 = 27

	// extensions with 'fake' prefix break connection, if server echoes them back
	fakeExtensionTokenBinding         uint16 = 24
	fakeExtensionChannelIDOld         uint16 = 30031 // not IANA assigned
	fakeExtensionChannelID            uint16 = 30032 // not IANA assigned
	fakeExtensionALPS                 uint16 = 17513 // not IANA assigned
	fakeExtensionDelegatedCredentials uint16 = 34

	fakeRecordSizeLimit uint16 = 0x001c

	// https://datatracker.ietf.org/doc/html/rfc8879#section-7.2
	typeCompressedCertificate uint8 = 25
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = uint16(0x0032)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = uint16(0x006b)
	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = uint16(0x0067)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)

	// https://docs.microsoft.com/en-us/dotnet/api/system.net.security.tlsciphersuite?view=netcore-3.1
	FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = uint16(0xc008)
)

// newest signatures
var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303

	FakeSHA1WithDSA   SignatureScheme = 0x0202
	FakeSHA256WithDSA SignatureScheme = 0x0402

	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// fake curves(groups)
var (
	FakeFFDHE2048 = uint16(0x0100)
	FakeFFDHE3072 = uint16(0x0101)
)

// https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 0x0001
	CertCompressionBrotli CertCompressionAlgo = 0x0002
	CertCompressionZstd   CertCompressionAlgo = 0x0003
)

const (
	PskModePlain uint8 = pskModePlain
	PskModeDHE   uint8 = pskModeDHE
)

type ClientHelloSpecFactory func() (ClientHelloSpec, error)

var EmptyClientHelloSpecFactory = func() (ClientHelloSpec, error) {
	return ClientHelloSpec{}, fmt.Errorf("please implement this method")
}

type ClientHelloID struct {
	Client string

	// Version specifies version of a mimicked clients (e.g. browsers).
	// Not used in randomized, custom handshake, and default Go.
	Version string

	// Seed is only used for randomized fingerprints to seed PRNG.
	// Must not be modified once set.
	Seed *PRNGSeed

	SpecFactory ClientHelloSpecFactory
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", p.Client, p.Version)
}

func (p *ClientHelloID) IsSet() bool {
	return (p.Client == "") && (p.Version == "")
}

func (p *ClientHelloID) ToSpec() (ClientHelloSpec, error) {
	return p.SpecFactory()
}

const (
	// clients
	helloGolang           = "Golang"
	helloRandomized       = "Randomized"
	helloRandomizedALPN   = "Randomized-ALPN"
	helloRandomizedNoALPN = "Randomized-NoALPN"
	helloCustomInternal   = "CustomInternal"
	helloFirefox          = "Firefox"
	helloOpera            = "Opera"
	helloChrome           = "Chrome"
	helloIOS              = "iOS"
	helloIPad             = "iPad"
	helloSafari           = "Safari"
	helloAndroid          = "Android"
	helloEdge             = "Edge"
	helloSafari           = "Safari"
	hello360              = "360Browser"
	helloQQ               = "QQBrowser"

	// versions
	helloAutoVers = "0"
)

type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions

	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = ClientHelloID{helloGolang, helloAutoVers, nil, EmptyClientHelloSpecFactory}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = ClientHelloID{helloCustomInternal, helloAutoVers, nil, EmptyClientHelloSpecFactory}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = ClientHelloID{helloRandomized, helloAutoVers, nil, EmptyClientHelloSpecFactory}
	HelloRandomizedALPN   = ClientHelloID{helloRandomizedALPN, helloAutoVers, nil, EmptyClientHelloSpecFactory}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomizedNoALPN, helloAutoVers, nil, EmptyClientHelloSpecFactory}

	// The rest will will parrot given browser.
	HelloFirefox_Auto = HelloFirefox_104
	HelloFirefox_55   = ClientHelloID{helloFirefox, "55", nil, EmptyClientHelloSpecFactory}
	HelloFirefox_56   = ClientHelloID{helloFirefox, "56", nil, EmptyClientHelloSpecFactory}
	HelloFirefox_63   = ClientHelloID{helloFirefox, "63", nil, EmptyClientHelloSpecFactory}
	HelloFirefox_65   = ClientHelloID{helloFirefox, "65", nil, EmptyClientHelloSpecFactory}
	HelloFirefox_99   = ClientHelloID{helloFirefox, "99", nil, EmptyClientHelloSpecFactory}
	HelloFirefox_102  = ClientHelloID{helloFirefox, "102", nil, EmptyClientHelloSpecFactory}
	HelloFirefox_104  = ClientHelloID{helloFirefox, "104", nil, EmptyClientHelloSpecFactory}

	HelloOpera_Auto = HelloOpera_90
	HelloOpera_90   = ClientHelloID{helloOpera, "90", nil, EmptyClientHelloSpecFactory}
	HelloOpera_89   = ClientHelloID{helloOpera, "89", nil, EmptyClientHelloSpecFactory}

	HelloChrome_Auto = HelloChrome_105
	HelloChrome_58   = ClientHelloID{helloChrome, "58", nil, EmptyClientHelloSpecFactory}
	HelloChrome_62   = ClientHelloID{helloChrome, "62", nil, EmptyClientHelloSpecFactory}
	HelloChrome_70   = ClientHelloID{helloChrome, "70", nil, EmptyClientHelloSpecFactory}
	HelloChrome_72   = ClientHelloID{helloChrome, "72", nil, EmptyClientHelloSpecFactory}
	HelloChrome_83   = ClientHelloID{helloChrome, "83", nil, EmptyClientHelloSpecFactory}
	HelloChrome_87   = ClientHelloID{helloChrome, "87", nil, EmptyClientHelloSpecFactory}
	HelloChrome_96   = ClientHelloID{helloChrome, "96", nil, EmptyClientHelloSpecFactory}
	HelloChrome_100  = ClientHelloID{helloChrome, "100", nil, EmptyClientHelloSpecFactory}
	HelloChrome_102  = ClientHelloID{helloChrome, "102", nil, EmptyClientHelloSpecFactory}
	HelloChrome_103  = ClientHelloID{helloChrome, "103", nil, EmptyClientHelloSpecFactory}
	HelloChrome_104  = ClientHelloID{helloChrome, "104", nil, EmptyClientHelloSpecFactory}
	HelloChrome_105  = ClientHelloID{helloChrome, "105", nil, EmptyClientHelloSpecFactory}

	HelloIOS_Auto = HelloIOS_16_0
	HelloIOS_11_1 = ClientHelloID{helloIOS, "111", nil, EmptyClientHelloSpecFactory} // legacy "111" means 11.1
	HelloIOS_12_1 = ClientHelloID{helloIOS, "12.1", nil, EmptyClientHelloSpecFactory}
	HelloIOS_13   = ClientHelloID{helloIOS, "13", nil, EmptyClientHelloSpecFactory}
	HelloIOS_14   = ClientHelloID{helloIOS, "14", nil, EmptyClientHelloSpecFactory}
	HelloIOS_15_5 = ClientHelloID{helloIOS, "15.5", nil, EmptyClientHelloSpecFactory}
	HelloIOS_15_6 = ClientHelloID{helloIOS, "15.6", nil, EmptyClientHelloSpecFactory}
	HelloIOS_16_0 = ClientHelloID{helloIOS, "16.0", nil, EmptyClientHelloSpecFactory}

	HelloIPad_Auto = HelloIPad_15_6
	HelloIPad_15_6 = ClientHelloID{helloIPad, "15.6", nil, EmptyClientHelloSpecFactory}

	HelloSafari_Auto   = HelloSafari_16_0
	HelloSafari_15_3   = ClientHelloID{helloSafari, "15.3", nil, EmptyClientHelloSpecFactory}
	HelloSafari_15_6_1 = ClientHelloID{helloSafari, "15.6.1", nil, EmptyClientHelloSpecFactory}
	HelloSafari_16_0   = ClientHelloID{helloSafari, "16.0", nil, EmptyClientHelloSpecFactory}

	HelloAndroid_11_OkHttp = ClientHelloID{helloAndroid, "11", nil, EmptyClientHelloSpecFactory}

	HelloEdge_Auto = HelloEdge_85 // HelloEdge_106 seems to be incompatible with this library
	HelloEdge_85   = ClientHelloID{helloEdge, "85", nil}
	HelloEdge_106  = ClientHelloID{helloEdge, "106", nil}

	HelloSafari_Auto = HelloSafari_16_0
	HelloSafari_16_0 = ClientHelloID{helloSafari, "16.0", nil}

	Hello360_Auto = Hello360_7_5 // Hello360_11_0 seems to be incompatible with this library
	Hello360_7_5  = ClientHelloID{hello360, "7.5", nil}
	Hello360_11_0 = ClientHelloID{hello360, "11.0", nil}

	HelloQQ_Auto = HelloQQ_11_1
	HelloQQ_11_1 = ClientHelloID{helloQQ, "11.1", nil}
)

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	} else {
		return v
	}
}

// utlsMacSHA384 returns a SHA-384 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func utlsMacSHA384(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	}...)
}

// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
// This provides better compatibility with servers on the web, but weakens security. Feel free
// to use this option if you establish additional secure connection inside of utls connection.
// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
// Must be called before establishing any connections.
func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}

package getcert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
)

type CertDescription struct {
	Name     pkix.Name
	Cipher   *CipherDescription
	Verified bool
}

func Fetch(host string) (*CertDescription, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	_, _, err := net.SplitHostPort(host)
	if err != nil {
		host += ":443"
	}

	conn, err := tls.Dial("tcp", host, nil)
	if err != nil {
		conn, err = tls.Dial("tcp", host, cfg)
	}

	if err != nil {
		return nil, err
	}

	defer conn.Close()

	var verified bool
	cert := conn.ConnectionState().PeerCertificates[0]
	if len(conn.ConnectionState().VerifiedChains) != 0 {
		for _, chain := range conn.ConnectionState().VerifiedChains {
			if bytes.Equal(cert.Raw, chain[0].Raw) {
				verified = true
			}
		}
	}

	certDescr := &CertDescription{
		Name:     cert.Subject,
		Cipher:   suiteToDescription(conn.ConnectionState().CipherSuite),
		Verified: verified,
	}

	return certDescr, nil
}

type CipherDescription struct {
	PK       string
	FS       string
	Sym      string
	Strength string
	Security string
}

const (
	noForwardSec  = "The server doesn't support forward secrecy. This is bad."
	forwardSec    = "The server does support forward secrecy. This is good!"
	rsaDescr      = "The server uses a key exchange and signature cipher (RSA) that many cryptographers suspect will be broken in the not-so-distant future. However, this cipher is prevalent in TLS certificates."
	eccDescr      = "The server uses the preferred key exchange and signature cipher (ECDHE / ECDSA)."
	hybridDescr   = "This server uses the preferred key exchange cipher (ECDHE) but uses a signature cipher (RSA) that many cryptographers suspect will be broken in the not-so-distant future."
	rc4Descr      = "The server uses a data security cipher that protects against certain attacks, but is thought to be otherwise weak (RC4)."
	tdesDescr     = "The server uses an outdated data security cipher (3DES)."
	aesCBCDescr   = "The server uses a standard and accepted data security cipher (AES-CBC). However, it may be vulnerable to certain attacks."
	aesGCMDescr   = "The server uses a standard and accepted data security cipher (AES-GCM). It uses a theoretically better (and potentially more fragile) method for securing data. This is the best choice at this time."
	strength128   = "The server uses strong cryptography."
	strength256   = "The server uses very strong cryptography."
	strengthOther = "The server uses potentially weak cryptography."
	unknown       = "We couldn't figure out the encryption used by the server."
)

func suiteToDescription(suite uint16) *CipherDescription {
	var cd CipherDescription

	switch suite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		cd.FS = noForwardSec
		cd.PK = rsaDescr
		cd.Sym = rc4Descr
		cd.Strength = strength128
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		cd.FS = noForwardSec
		cd.PK = rsaDescr
		cd.Sym = tdesDescr
		cd.Strength = strengthOther
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		cd.FS = noForwardSec
		cd.PK = rsaDescr
		cd.Sym = aesCBCDescr
		cd.Strength = strength128
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		cd.FS = noForwardSec
		cd.PK = rsaDescr
		cd.Sym = aesCBCDescr
		cd.Strength = strength256
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		cd.FS = forwardSec
		cd.PK = eccDescr
		cd.Sym = rc4Descr
		cd.Strength = strength128
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		cd.FS = forwardSec
		cd.PK = eccDescr
		cd.Sym = aesCBCDescr
		cd.Strength = strength128
		cd.Strength = strength128
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		cd.FS = forwardSec
		cd.PK = eccDescr
		cd.Sym = aesCBCDescr
		cd.Security = strength256
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		cd.FS = forwardSec
		cd.PK = hybridDescr
		cd.Sym = rc4Descr
		cd.Strength = strength128
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		cd.FS = forwardSec
		cd.PK = hybridDescr
		cd.Sym = tdesDescr
		cd.Security = strengthOther
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		cd.FS = forwardSec
		cd.PK = hybridDescr
		cd.Sym = aesCBCDescr
		cd.Strength = strength128
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		cd.FS = forwardSec
		cd.PK = hybridDescr
		cd.Sym = aesCBCDescr
		cd.Strength = strength256
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		cd.FS = forwardSec
		cd.PK = hybridDescr
		cd.Sym = aesGCMDescr
		cd.Strength = strength128
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		cd.FS = forwardSec
		cd.PK = eccDescr
		cd.Sym = aesGCMDescr
		cd.Strength = strength128
	default:
		cd.FS = unknown
		cd.PK = unknown
		cd.Sym = unknown
		cd.Strength = unknown
	}
	return &cd
}

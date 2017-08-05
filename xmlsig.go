// Package xmlsig supports add XML Digital Signatures to Go structs marshalled to XML.
package xmlsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
)

// Signer is used to create a Signature for the provided object.
type Signer interface {
	Sign(interface{}) (*Signature, error)
}

type signer struct {
	cert string
	key  *rsa.PrivateKey
}

// NewSigner creates a new Signer with the provided key and certificate. Key is used to create the signature. The certificate added to the Signature's keyinfo
func NewSigner(key io.Reader, cert io.Reader) (Signer, error) {
	// We're going to use the key for signing, but the cert is just for including in the signature block.
	// Store it as a string.
	keyPem, err := readPEM(key)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, err
	}
	// A little bit of unneeded work to decode the cert, but it makes sure the file is good.
	certPem, err := readPEM(cert)
	if err != nil {
		return nil, err
	}
	return &signer{base64.StdEncoding.EncodeToString(certPem.Bytes), privateKey}, nil
}

func readPEM(pemReader io.Reader) (*pem.Block, error) {
	if pemReader == nil {
		return nil, errors.New("PEM cannot be nil")
	}
	pemData, err := ioutil.ReadAll(pemReader)
	if err != nil {
		return nil, err
	}
	decodedPem, _ := pem.Decode(pemData)
	if decodedPem == nil {
		return nil, errors.New("no PEM data found")
	}
	return decodedPem, nil
}

func (s *signer) Sign(data interface{}) (*Signature, error) {
	signature := newSignature()
	// canonicalize the Item
	canonData, id, err := canonicalize(data)
	if err != nil {
		return nil, err
	}
	if id != "" {
		signature.SignedInfo.Reference.URI = "#" + id
	}
	// calculate the digest
	digest := digest(canonData)
	signature.SignedInfo.Reference.DigestValue = digest
	// canonicalize the SignedInfo
	canonData, _, err = canonicalize(signature.SignedInfo)
	if err != nil {
		return nil, err
	}
	sig, err := sign(s.key, canonData)
	if err != nil {
		return nil, err
	}
	signature.SignatureValue = sig
	signature.KeyInfo.X509Data.X509Certificate = s.cert
	return signature, nil
}

func sign(key *rsa.PrivateKey, data []byte) (string, error) {
	h := sha1.New()
	h.Write(data)
	sum := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func newSignature() *Signature {
	signature := &Signature{}
	signature.SignedInfo.CanonicalizationMethod.Algorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	signature.SignedInfo.SignatureMethod.Algorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	transforms := &signature.SignedInfo.Reference.Transforms.Transform
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2001/10/xml-exc-c14n#"})
	signature.SignedInfo.Reference.DigestMethod.Algorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
	return signature
}

func digest(data []byte) string {
	h := sha1.New()
	h.Write(data)
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}

package xmlsig

import ("io"
    "crypto/rsa"
    "errors"
    "io/ioutil"
    "encoding/pem"
    "crypto/x509"
    "encoding/base64"
    "bytes"
    "crypto/sha1"
    "crypto/rand"
    "crypto"
    "bufio"
    "encoding/xml"
    "fmt"
    "sort")

type Signer interface {
    Sign(interface{}) (*Signature, error)
}

type signer struct {
    cert string
    key *rsa.PrivateKey
}

func NewSigner(key io.Reader, cert io.Reader) (Signer, error) {
    // We're going to use the key for signing, but the cert is just for including in the signature block.
    // Store it as a string.
    keyPem, err := readPEM(key)
    if err!=nil {
        return nil, err
    }
    privateKey, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)
    if err!=nil {
        return nil, err
    }
    // A little bit of unneeded work to decode the cert, but it makes sure the file is good.
    certPem, err := readPEM(cert)
    if err!=nil {
        return nil, err
    }
    return &signer{base64.StdEncoding.EncodeToString(certPem.Bytes), privateKey}, nil
}

func readPEM(pemReader io.Reader) (*pem.Block, error) {
    if pemReader == nil {
        return nil, errors.New("PEM cannot be nil.")
    }
    pemData, err := ioutil.ReadAll(pemReader)
    if err!=nil {
        return nil, err
    }
    decodedPem, _ := pem.Decode(pemData)
    if decodedPem==nil {
        return nil, errors.New("No PEM data found.")
    }
    return decodedPem, nil
}

type Signature struct {
    XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
    SignedInfo SignedInfo
    SignatureValue string `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
    KeyInfo KeyInfo
}

type Algorithm struct {
    Algorithm string `xml:",attr"`
}

type SignedInfo struct {
    XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
    CanonicalizationMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
    SignatureMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
    Reference Reference
}

type Reference struct {
    XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
    URI string `xml:",attr,omitempty"`
    Transforms Transforms
    DigestMethod Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
    DigestValue string `xml:"http://www.w3.org/2000/09/xmldsig# DigestValue"`
}

type Transforms struct {
    XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
    Transform []Algorithm `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
}

type KeyInfo  struct {
    XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
    X509Data X509Data
}

type X509Data struct {
    XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
    X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

func (s *signer) Sign(data interface{}) (*Signature, error) {
    signature := newSignature()
    // canonicalize the Item
    canonData, id, err := canonicalize(data)
    if err!=nil {
        return nil, err
    }
    if id!="" {
        signature.SignedInfo.Reference.URI="#"+id
    }
    // calculate the digest
    digest := digest(canonData)
    signature.SignedInfo.Reference.DigestValue = digest
    // canonicalize the SignedInfo
    canonData, _, err=canonicalize(signature.SignedInfo)
    if err!=nil {
        return nil, err
    }
    sig, err := sign(s.key, canonData)
    if err!=nil {
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
    if err!=nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(sig), nil
}

func newSignature() *Signature {
    signature := &Signature{}
    signature.SignedInfo.CanonicalizationMethod.Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    signature.SignedInfo.SignatureMethod.Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    transforms := &signature.SignedInfo.Reference.Transforms.Transform
    *transforms = append(*transforms, Algorithm{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
    *transforms = append(*transforms, Algorithm{"http://www.w3.org/2001/10/xml-exc-c14n#"})
    signature.SignedInfo.Reference.DigestMethod.Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"
    return signature
}

func digest(data []byte) string {
    h := sha1.New()
    h.Write(data)
    sum := h.Sum(nil)
    return base64.StdEncoding.EncodeToString(sum)
}

func canonicalize(data interface{}) ([]byte, string, error) {
    // write the item to a buffer
    var buffer, out bytes.Buffer
    writer := bufio.NewWriter(&buffer)
    encoder := xml.NewEncoder(writer)
    encoder.Encode(data)
    encoder.Flush()
    // read it back in
    decoder := xml.NewDecoder(bytes.NewReader(buffer.Bytes()))
    stack := &Stack{}
    outWriter := bufio.NewWriter(&out)
    firstElem := true
    id := ""
    writeStartElement := func(writer io.Writer, start xml.StartElement) {
        fmt.Fprintf(writer, "<%s", start.Name.Local)
        sort.Sort(CanonAtt(start.Attr))
        currentNs, err := stack.Top()
        if err!=nil {
            // No namespaces yet declare ours
            fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", start.Name.Space)
        }else {
            // Different namespace declare ours
            if currentNs!=start.Name.Space {
                fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", start.Name.Space)
            }
        }
        stack.Push(start.Name.Space)
        for i := range (start.Attr) {
            if "xmlns" != start.Attr[i].Name.Local {
                fmt.Fprintf(writer, " %s=\"%s\"", start.Attr[i].Name.Local, start.Attr[i].Value)
            }
        }
        fmt.Fprint(writer, ">")
    }
    for {
        token, err := decoder.Token()
        if err != nil {
            break
        }
        switch t := token.(type) {
            case xml.StartElement:
            // Check the first element for an ID to include in the reference
            if firstElem {
                firstElem = false
                for i := range (t.Attr) {
                    if "ID"==t.Attr[i].Name.Local {
                        id = t.Attr[i].Value
                    }
                }
            }
            writeStartElement(outWriter, t)

            case xml.EndElement:
            stack.Pop()
            fmt.Fprintf(outWriter, "</%s>", t.Name.Local)

            case xml.CharData:
            outWriter.Write(t)
        }
    }
    outWriter.Flush()
    return out.Bytes(), id, nil
}

type CanonAtt []xml.Attr

func (att CanonAtt) Len() int {
    return len(att)
}

func (att CanonAtt) Swap(i, j int) {
    att[i], att[j] = att[j], att[i]
}

func (att CanonAtt) Less(i, j int) bool {
    iName := att[i].Name.Local
    jName := att[j].Name.Local
    if iName=="xmlns" {
        return true
    }
    if jName=="xmlns" {
        return false
    }
    return att[i].Name.Local < att[j].Name.Local
}

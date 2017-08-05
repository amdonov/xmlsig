I wrote this to sign XML documents produced by using Go's default XML encoder. It's not capable of signing arbitrary XML. The following example shows how to produce a simple signature.

    import ("github.com/amdonov/xmlsig"
        "os"
        "encoding/xml")

    func Example() {
        doc := Test1{}
        doc.Data = "Hello, World!"
        doc.ID = "1234"
        key, _ := os.Open("server.pem")
        defer key.Close()
        cert, _ := os.Open("server.crt")
        signer, _ := xmlsig.NewSigner(key, cert)
        sig, _ := signer.Sign(doc)
        doc.Signature = sig
        encoder := xml.NewEncoder(os.Stdout)
        encoder.Encode(doc)
    }

    type Test1 struct {
        XMLName xml.Name `xml:"urn:envelope Envelope"`
        ID string `xml:",attr"`
        Data string `xml:"urn:envelope Data"`
        Signature *xmlsig.Signature
    }
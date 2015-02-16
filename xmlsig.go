package xmlsig

//#cgo pkg-config: libxml-2.0
//#include "xmlsig.h"
import "C"
import ("io"
    "crypto/rsa"
    "errors"
    "io/ioutil"
    "encoding/pem"
    "crypto/x509"
    "encoding/base64"
    "unsafe"
    "bytes"
    "reflect"
    "crypto/sha1"
    "crypto/rand"
    "crypto"
    "text/template"
    "bufio")

func Initialize() {
    C.init()
}

func Terminate() {
    C.xmlCleanupParser()
}

type Signer interface {
    Sign(io.Reader, string) (*XML, error)
}

type signer struct {
    cert string
    key *rsa.PrivateKey
}

func (s *signer) Sign(xml io.Reader, id string) (*XML, error) {
    // Read the XML into memory
    doc, err := readXML(xml)
    if err!=nil {
        return nil, err
    }
    defer C.xmlFreeDoc(doc)
    root := C.xmlDocGetRootElement(doc)
    if root==nil {
        return nil, errors.New("Document missing root element.")
    }
    // Find the node with the referenced id
    reference := findElementByID(root, id)
    if reference==nil {
        return nil, errors.New("Failed to find element with ID="+id)
    }
    // Canonicalize the node
    refData, err := canonicalize(&reference)
    if err!=nil {
        return nil, err
    }
    defer refData.Free()
    // Calculate the digest
    dataDigest := digest(refData)
    // Create a document containing the signature template
    sigTemplate, err := newSignatureTemplate(id, s.cert)
    if err!=nil {
        return nil, err
    }
    sigDoc, err := readXML(sigTemplate)
    sigNode := C.xmlDocGetRootElement(sigDoc)
    // Set the digest value
    digestNode := findElementByName(sigNode, "DigestValue", "http://www.w3.org/2000/09/xmldsig#")
    C.xmlNodeSetContent(digestNode, xmlFromstr(dataDigest))
    // Canonicalize the signature info
    infoNode := findElementByName(sigNode, "SignedInfo", "http://www.w3.org/2000/09/xmldsig#")
    if infoNode==nil {
        return nil, errors.New("Failed to find SignedInfo element.")

    }
    infoData, err := canonicalize(&infoNode)
    if err!=nil {
        return nil, err
    }
    defer infoData.Free()
    // Sign the signature info
    infoSignature, err := sign(s.key, infoData)
    if err!=nil {
        return nil, err
    }
    // Set the signature value
    valueNode := findElementByName(sigNode, "SignatureValue", "http://www.w3.org/2000/09/xmldsig#")
    if valueNode ==nil {
        return nil, errors.New("Failed to find SignatureValue element.")
    }
    C.xmlNodeSetContent(valueNode, xmlFromstr(infoSignature))
    // Append the signature to the document
    signatureCopy := C.xmlDocCopyNode(sigNode, doc, 1)
    C.xmlAddChild(reference, signatureCopy)
    // Return the signed document
    var signedDoc *C.xmlChar
    var size C.int
    C.xmlDocDumpMemory(doc, &signedDoc, &size)
    return newXML(signedDoc, size), nil
}

func sign(key *rsa.PrivateKey, data io.Reader) (string, error) {
    h := sha1.New()
    io.Copy(h, data)
    sum := h.Sum(nil)
    sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum)
    if err!=nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(sig), nil
}

func digest(xml io.Reader) string {
    h := sha1.New()
    io.Copy(h, xml)
    sum := h.Sum(nil)
    return base64.StdEncoding.EncodeToString(sum)
}

func (s *signer) getSignatureDoc(id string) (C.xmlDocPtr, error) {
    templ, err := newSignatureTemplate(id, s.cert)
    if err!=nil {
        return nil, err
    }
    return readXML(templ)
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

// Helper to go from libxml2's xmlChar to string
func strFromXml(text *C.xmlChar) string {
    return C.GoString((*C.char)(unsafe.Pointer(text)))
}

// Helper to go from string to libxml2's xmlChar. Should be freed.
func xmlFromstr(text string) *C.xmlChar {
    return (*C.xmlChar)(unsafe.Pointer(C.CString(text)))
}

// Walks an element trying to match a node that satisfies the checker function
func findElement(parent C.xmlNodePtr, checker func(C.xmlNodePtr) C.xmlNodePtr) C.xmlNodePtr {
    cur := parent
    for cur!=nil {
        if res := checker(cur); res!=nil {
            return res
        }
        if cur.children !=nil {
            ret := findElement(cur.children, checker)
            if ret!=nil {
                return ret
            }
        }
        cur = cur.next
    }
    return nil
}

func findElementByID(parent C.xmlNodePtr, id string) C.xmlNodePtr {
    // value of XML_ELEMENT_NODE
    elementType := C.xmlElementType(1)
    return findElement(parent, func(node C.xmlNodePtr) C.xmlNodePtr {
        idAtt := xmlFromstr("ID")
        defer C.free(unsafe.Pointer(idAtt))
        if node._type == elementType {
            // Found an element look at the attributes
            if idVal := C.xmlGetNoNsProp(node, idAtt); idVal!=nil {
                val := strFromXml(idVal)
                if id==val {
                    return node
                }
            }
        }
        return nil
    })
}

func findElementByName(parent C.xmlNodePtr, name string, ns string) C.xmlNodePtr {
    // value of XML_ELEMENT_NODE
    elementType := C.xmlElementType(1)
    return findElement(parent, func(node C.xmlNodePtr) C.xmlNodePtr {
        // TODO check the namespace
        if node._type == elementType {
            eName := strFromXml(node.name)
            if eName == name {
                return node
            }
        }
        return nil
    })
}

func readXML(xml io.Reader) (C.xmlDocPtr, error) {
    if xml == nil {
        return nil, errors.New("No XML provided.")
    }
    xmlData, err := ioutil.ReadAll(xml)
    if err!=nil {
        return nil, err
    }
    size := C.int(len(xmlData))
    if size<1 {
        return nil, errors.New("Failed to read XML.")
    }
    doc := C.xmlParseMemory((*C.char)(unsafe.Pointer(&xmlData[0])), size)
    if doc == nil {
        return nil, errors.New("Failed to parse XML.")
    }
    return doc, nil
}

type XML struct {
    io.Reader
    data *C.xmlChar
}

// I found that I had to use the pointer to work properly
func canonicalize(node *C.xmlNodePtr) (*XML, error) {
    // Make a new document an copy the node to it.
    // TODO work on doing this without making a copy
    version := xmlFromstr("1.0")
    defer C.free(unsafe.Pointer(version))
    doc := C.xmlNewDoc(version)
    defer C.xmlFreeDoc(doc)
    if *node==nil {
        return nil, errors.New("Source node was null.")
    }
    rootNode := C.xmlDocCopyNode(*node, doc, 1)
    if rootNode==nil {
        return nil, errors.New("XML Copy did not return any nodes.")
    }
    C.xmlDocSetRootElement(doc, rootNode)
    var res *C.xmlChar
    size := C.canonicalize(doc, &res)
    if size==0 {
        return nil, errors.New("Canonicalization didn't return any data.")
    }
    return newXML(res, size), nil
}

func newXML(data *C.xmlChar, size C.int) *XML {
    // Create a byte[] slice of the data
    hdr := reflect.SliceHeader{
        Data: uintptr(unsafe.Pointer(data)),
        Len:  int(size),
        Cap:  int(size),
    }
    xmlBytes := *(*[]byte)(unsafe.Pointer(&hdr))
    return &XML{bytes.NewReader(xmlBytes), data}
}

// Decided to manage memory explicitly rather than use a runtime finalizer
func (xml *XML) Free() {
    C.free(unsafe.Pointer(xml.data))
}

type signatureData struct {
    Id string
    Cert string
}

// Given a certificate and node ID, returns the XML fragment for the Signature block
func newSignatureTemplate(id string, cert string) (io.Reader, error) {
    t := template.New("signature")
    t.Parse(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <Reference URI="#{{ .Id }}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><DigestValue></DigestValue></Reference></SignedInfo><SignatureValue></SignatureValue><KeyInfo>
    <X509Data><X509Certificate>{{ .Cert }}</X509Certificate></X509Data></KeyInfo></Signature>`)
    var buffer bytes.Buffer
    writer := bufio.NewWriter(&buffer)
    err := t.Execute(writer, signatureData{id, cert})
    if err!=nil {
        return nil, err
    }
    writer.Flush()
    return bytes.NewReader(buffer.Bytes()), nil
}
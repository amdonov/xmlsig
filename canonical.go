package xmlsig

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
)

func canonicalize(data interface{}) ([]byte, string, error) {
	// write the item to a buffer
	var buffer, out bytes.Buffer
	writer := bufio.NewWriter(&buffer)
	encoder := xml.NewEncoder(writer)
	encoder.Encode(data)
	encoder.Flush()
	// read it back in
	decoder := xml.NewDecoder(bytes.NewReader(buffer.Bytes()))
	stack := &stack{}
	outWriter := bufio.NewWriter(&out)
	firstElem := true
	id := ""
	writeStartElement := func(writer io.Writer, start xml.StartElement) {
		fmt.Fprintf(writer, "<%s", start.Name.Local)
		sort.Sort(canonAtt(start.Attr))
		currentNs, err := stack.Top()
		if err != nil {
			// No namespaces yet declare ours
			fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", start.Name.Space)
		} else {
			// Different namespace declare ours
			if currentNs != start.Name.Space {
				fmt.Fprintf(writer, " %s=\"%s\"", "xmlns", start.Name.Space)
			}
		}
		stack.Push(start.Name.Space)
		for i := range start.Attr {
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
				for i := range t.Attr {
					if "ID" == t.Attr[i].Name.Local {
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

type canonAtt []xml.Attr

func (att canonAtt) Len() int {
	return len(att)
}

func (att canonAtt) Swap(i, j int) {
	att[i], att[j] = att[j], att[i]
}

func (att canonAtt) Less(i, j int) bool {
	iName := att[i].Name.Local
	jName := att[j].Name.Local
	if iName == "xmlns" {
		return true
	}
	if jName == "xmlns" {
		return false
	}
	return att[i].Name.Local < att[j].Name.Local
}

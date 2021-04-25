package export

import (
	"bytes"
	"fmt"
	"html/template"
)

func Export(view interface{}, t string) ([]byte, error) {
	tmpl, err := template.New("ovpn-client").Parse(t)
	if err != nil {
		return []byte{}, fmt.Errorf("can't parse client template: %s", err)
	}

	buf := bytes.NewBufferString("")
	err = tmpl.Execute(buf, view)
	return buf.Bytes(), fmt.Errorf("can't fill out client template: %s", err)

}

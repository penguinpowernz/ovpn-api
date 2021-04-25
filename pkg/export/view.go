package export

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/opencoff/go-pki"
)

type View struct {
	CommonName string
	Date       string
	Tool       string
	Cert       string
	Key        string
	Ca         string
	TlsCrypt   string

	ServerCommonName string

	// IP Address of server. If present, this is used for server.
	IP string

	// DNS name of the server. If present, this is used for the client.
	// The client template can choose one over the other.
	Host string
	Port uint16
}

func NewServerView(svr *pki.Cert, caPEM []byte) (x *View, err error) {
	x.Port = 1194
	x.Ca = string(caPEM)
	x.Date = time.Now().UTC().Format(time.RFC1123Z)
	x.IP = "0.0.0.0"
	x.Tool = "ovpn-api"

	var sd *srvdata
	sd, err = decodeAdditional(svr.Additional)
	if err != nil {
		return
	}

	x.ServerCommonName = svr.Subject.CommonName
	if len(svr.IPAddresses) > 0 {
		x.IP = svr.IPAddresses[0].String()
	}

	// We only use the first name in the DNSNames list - if it is present.
	if len(svr.DNSNames) > 0 {
		x.Host = svr.DNSNames[0]
	} else {
		// Punt and use the IP address.
		// This way, the client template can refer to .Host to
		// get the Hostname or IP address
		x.Host = x.IP
	}

	if sd != nil {
		x.Port = sd.Port
		if x.Port == 0 {
			x.Port = 1194
		}

		if len(sd.TLS) > 0 {
			x.TlsCrypt, err = fmtTLS(sd.TLS)
		}
	}

	crt, key := svr.PEM()
	x.Cert = string(crt)
	x.Key = string(key)
	x.CommonName = svr.Subject.CommonName
	return
}

func NewClientView(c *pki.Cert, svr *pki.Cert, caPEM []byte) (x *View, err error) {
	x.Port = 1194
	x.Ca = string(caPEM)
	x.Date = time.Now().UTC().Format(time.RFC1123Z)
	x.IP = "0.0.0.0"
	x.Tool = "ovpn-api"

	if svr != nil {
		var sd *srvdata
		sd, err = decodeAdditional(svr.Additional)
		if err != nil {
			return
		}

		x.ServerCommonName = svr.Subject.CommonName
		if len(svr.IPAddresses) > 0 {
			x.IP = svr.IPAddresses[0].String()
		}

		// We only use the first name in the DNSNames list - if it is present.
		if len(svr.DNSNames) > 0 {
			x.Host = svr.DNSNames[0]
		} else {
			// Punt and use the IP address.
			// This way, the client template can refer to .Host to
			// get the Hostname or IP address
			x.Host = x.IP
		}

		if sd != nil {
			x.Port = sd.Port
			if x.Port == 0 {
				x.Port = 1194
			}

			if len(sd.TLS) > 0 {
				x.TlsCrypt, err = fmtTLS(sd.TLS)
			}
		}
	}

	crt, key := c.PEM()
	x.Cert = string(crt)
	x.Key = string(key)
	x.CommonName = c.Subject.CommonName
	return
}

func fmtTLS(b []byte) (string, error) {
	if len(b) < 256 {
		return "", errors.New("tls-crypt bytes are less than 256?")
	}

	const prefix string = `# DoS protection for TLS control channel
# encrypts & HMACs control channel with this symmetric key.
# Shared between server & clients.
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
`

	var s strings.Builder
	s.WriteString(prefix)
	for i := 0; i < 256; i += 16 {
		for j := 0; j < 16; j++ {
			v := b[j+i]
			s.WriteString(fmt.Sprintf("%02x", v))
		}

		s.WriteRune('\n')
	}

	s.WriteString("-----END OpenVPN Static key V1-----\n</tls-crypt>\n")
	return s.String(), nil
}

func decodeAdditional(eb []byte) (*srvdata, error) {
	if len(eb) == 0 {
		return nil, nil
	}

	var s srvdata

	b := bytes.NewBuffer(eb)
	g := gob.NewDecoder(b)
	if err := g.Decode(&s); err != nil {
		return nil, fmt.Errorf("can't decode additional data: %s", err)
	}
	return &s, nil
}

type srvdata struct {
	Port uint16
	TLS  []byte
}

// Encode additional info for a server
func encodeAdditional(s *srvdata) ([]byte, error) {

	var b bytes.Buffer
	g := gob.NewEncoder(&b)
	if err := g.Encode(s); err != nil {
		return nil, fmt.Errorf("can't encode additional data: %s", err)
	}

	return b.Bytes(), nil
}

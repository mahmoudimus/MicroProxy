// A TLS 1.3 server with Encrypted Client Hello (RFC 9849), for EchInteropTest: Go's crypto/tls
// server side of ECH. It makes an ECH key, prints the ECHConfigList clients should use
// ("ECHCONFIGS <base64>"), one for a key it does not have ("STALE <base64>"), and the port it
// listens on ("LISTEN <port>"); then for each connection it writes the inner (or only) server
// name and whether ECH was accepted, and echoes one line back.
//
// Run with: go run main.go -cert c.pem -key k.pem -public-cert pc.pem -public-key pk.pem -public-name public.test
package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

func echConfig(id uint8, pub []byte, publicName string, aeads []uint16, maxNameLength uint8) []byte {
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, uint16(4*len(aeads)))
	for _, a := range aeads {
		c = binary.BigEndian.AppendUint16(c, 0x0001) // HKDF-SHA256
		c = binary.BigEndian.AppendUint16(c, a)
	}
	c = append(c, maxNameLength, uint8(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	out := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...)
}

func list(configs ...[]byte) []byte {
	var body []byte
	for _, c := range configs {
		body = append(body, c...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

func main() {
	certFile := flag.String("cert", "", "certificate chain PEM for the inner name")
	keyFile := flag.String("key", "", "private key PEM for the inner name")
	publicCertFile := flag.String("public-cert", "", "certificate chain PEM for the public name")
	publicKeyFile := flag.String("public-key", "", "private key PEM for the public name")
	publicName := flag.String("public-name", "public.test", "the ECHConfig public_name")
	aeadList := flag.String("aeads", "1", "HPKE AEAD ids the config offers, comma separated")
	curves := flag.String("curves", "", "comma-separated curve ids the server accepts (default: Go's)")
	maxName := flag.Int("max-name-length", 64, "the ECHConfig maximum_name_length")
	flag.Parse()

	var aeads []uint16
	for _, a := range strings.Split(*aeadList, ",") {
		v, err := strconv.Atoi(a)
		if err != nil {
			log.Fatal(err)
		}
		aeads = append(aeads, uint16(v))
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	stale, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	config := echConfig(7, key.PublicKey().Bytes(), *publicName, aeads, uint8(*maxName))
	staleConfig := echConfig(9, stale.PublicKey().Bytes(), *publicName, aeads, uint8(*maxName))

	inner, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatal(err)
	}
	outer, err := tls.LoadX509KeyPair(*publicCertFile, *publicKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{inner, outer},
		NextProtos:   []string{"h2", "http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
			Config: config, PrivateKey: key.Bytes(), SendAsRetry: true,
		}},
	}
	if *curves != "" {
		for _, c := range strings.Split(*curves, ",") {
			v, err := strconv.Atoi(c)
			if err != nil {
				log.Fatal(err)
			}
			cfg.CurvePreferences = append(cfg.CurvePreferences, tls.CurveID(v))
		}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ECHCONFIGS " + base64.StdEncoding.EncodeToString(list(config)))
	fmt.Println("STALE " + base64.StdEncoding.EncodeToString(list(staleConfig)))
	fmt.Printf("LISTEN %d\n", ln.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(conn.(*tls.Conn))
	}
}

func serve(conn *tls.Conn) {
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		fmt.Fprintln(os.Stderr, "handshake:", err)
		return
	}
	st := conn.ConnectionState()
	fmt.Fprintf(conn, "sni=%s ech=%t group=%d\n", st.ServerName, st.ECHAccepted, st.CurveID)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return
	}
	conn.Write([]byte("echo " + line))
}

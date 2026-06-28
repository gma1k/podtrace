// Package quicinitial extracts the SNI (server name) from a QUIC v1 Initial
// packet.
package quicinitial

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// quicV1InitialSalt is the fixed salt for QUIC v1 initial-secret derivation
// (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExtract = HMAC-SHA256(salt, ikm) (RFC 5869).
func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpand derives length bytes from prk+info (RFC 5869).
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// hkdfExpandLabel implements the TLS 1.3 / QUIC labeled HKDF-Expand
// (RFC 8446 §7.1): the info is a structured HkdfLabel with the "tls13 " prefix.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte((length>>8)&0xff), byte(length&0xff))
	info = append(info, byte(len(full)&0xff))
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdfExpand(secret, info, length)
}

// InitialKeys holds the client-side Initial protection keys.
type InitialKeys struct {
	Key []byte
	IV  []byte
	HP  []byte
}

// DeriveClientInitialKeys derives the client Initial keys from the Destination
// Connection ID (RFC 9001 §5.2).
func DeriveClientInitialKeys(dcid []byte) InitialKeys {
	initialSecret := hkdfExtract(quicV1InitialSalt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	return InitialKeys{
		Key: hkdfExpandLabel(clientSecret, "quic key", 16),
		IV:  hkdfExpandLabel(clientSecret, "quic iv", 12),
		HP:  hkdfExpandLabel(clientSecret, "quic hp", 16),
	}
}

// readVarint reads a QUIC variable-length integer (RFC 9000 §16) at off,
// returning the value and the number of bytes consumed.
func readVarint(b []byte, off int) (uint64, int, bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	prefix := b[off] >> 6
	n := 1 << prefix
	if off+n > len(b) {
		return 0, 0, false
	}
	v := uint64(b[off] & 0x3f)
	for i := 1; i < n; i++ {
		v = (v << 8) | uint64(b[off+i])
	}
	return v, n, true
}

func asLen(v uint64) (int, bool) {
	if v > 1<<20 {
		return 0, false
	}
	return int(v), true
}

// ExtractSNI parses a QUIC v1 long-header Initial packet and returns the SNI
// (server_name) from the client's ClientHello, or ("", false) if the packet is
// not a decodable client Initial or carries no SNI.
func ExtractSNI(b []byte) (string, bool) {
	s, err := extractSNI(b)
	return s, err == nil
}

func ExtractSNIErr(b []byte) (string, error) { return extractSNI(b) }

func extractSNI(b []byte) (string, error) {
	if len(b) < 7 {
		return "", fmt.Errorf("too short (%d)", len(b))
	}
	first := b[0]
	if first&0xC0 != 0xC0 || first&0x30 != 0x00 {
		return "", fmt.Errorf("not a long-header Initial (0x%02x)", first)
	}
	if binary.BigEndian.Uint32(b[1:5]) != 0x00000001 {
		return "", fmt.Errorf("not QUIC v1")
	}
	p := 5
	dcidLen := int(b[p])
	p++
	if p+dcidLen > len(b) {
		return "", fmt.Errorf("dcid out of range")
	}
	dcid := b[p : p+dcidLen]
	p += dcidLen
	if p >= len(b) {
		return "", fmt.Errorf("scid len out of range")
	}
	scidLen := int(b[p])
	p++
	p += scidLen
	tokenLen, n, ok := readVarint(b, p)
	if !ok {
		return "", fmt.Errorf("token len varint")
	}
	tl, ok := asLen(tokenLen)
	if !ok {
		return "", fmt.Errorf("token len too large")
	}
	p += n + tl
	lengthVarint, n, ok := readVarint(b, p)
	if !ok {
		return "", fmt.Errorf("length varint")
	}
	length, ok := asLen(lengthVarint)
	if !ok {
		return "", fmt.Errorf("length too large")
	}
	p += n
	pnOffset := p
	if pnOffset+length > len(b) || length < 20 {
		return "", fmt.Errorf("length %d vs buf %d (pnOffset %d)", length, len(b), pnOffset)
	}

	keys := DeriveClientInitialKeys(dcid)

	sampleOff := pnOffset + 4
	if sampleOff+16 > len(b) {
		return "", fmt.Errorf("sample out of range")
	}
	block, err := aes.NewCipher(keys.HP)
	if err != nil {
		return "", err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, b[sampleOff:sampleOff+16])

	hdr := make([]byte, pnOffset+4)
	copy(hdr, b[:pnOffset+4])
	hdr[0] = first ^ (mask[0] & 0x0f)
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] = b[pnOffset+i] ^ mask[(1+i)&0x0f]
		pn = (pn << 8) | uint64(hdr[pnOffset+i])
	}
	hdr = hdr[:pnOffset+pnLen]

	nonce := make([]byte, 12)
	copy(nonce, keys.IV)
	var pnbuf [8]byte
	binary.BigEndian.PutUint64(pnbuf[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnbuf[i]
	}
	gcm, err := cipher.NewGCM(block2(keys.Key))
	if err != nil {
		return "", err
	}
	ctStart := pnOffset + pnLen
	ctEnd := pnOffset + length
	if ctStart > ctEnd || ctEnd > len(b) {
		return "", fmt.Errorf("ciphertext range")
	}
	plain, err := gcm.Open(nil, nonce, b[ctStart:ctEnd], hdr)
	if err != nil {
		return "", fmt.Errorf("aead open: %w", err)
	}
	hs := reassembleCrypto(plain)
	if hs == nil {
		return "", fmt.Errorf("no CRYPTO frame")
	}
	sni, ok := parseClientHelloSNI(hs)
	if !ok {
		return "", fmt.Errorf("no SNI in ClientHello (hslen %d)", len(hs))
	}
	return sni, nil
}

// block2 builds an AES cipher for the GCM key.
func block2(key []byte) cipher.Block {
	b, _ := aes.NewCipher(key)
	return b
}

// reassembleCrypto concatenates the CRYPTO frames (type 0x06) in a decrypted
// Initial payload in offset order, returning the handshake bytes.
func reassembleCrypto(plain []byte) []byte {
	type chunk struct {
		off  int
		data []byte
	}
	var chunks []chunk
	maxEnd := 0
	i := 0
	for i < len(plain) {
		ft := plain[i]
		if ft == 0x00 || ft == 0x01 {
			i++
			continue
		}
		if ft != 0x06 {
			break
		}
		i++
		offv, n, ok := readVarint(plain, i)
		if !ok {
			break
		}
		i += n
		lv, n, ok := readVarint(plain, i)
		if !ok {
			break
		}
		i += n
		off, ok := asLen(offv)
		if !ok {
			break
		}
		l, ok := asLen(lv)
		if !ok || i+l > len(plain) {
			break
		}
		chunks = append(chunks, chunk{off: off, data: plain[i : i+l]})
		if off+l > maxEnd {
			maxEnd = off + l
		}
		i += l
	}
	if maxEnd == 0 || maxEnd > 1<<20 {
		return nil
	}
	out := make([]byte, maxEnd)
	for _, c := range chunks {
		copy(out[c.off:], c.data)
	}
	return out
}

// parseClientHelloSNI parses a TLS ClientHello handshake message and returns the
// server_name from the SNI extension.
func parseClientHelloSNI(hs []byte) (string, bool) {
	if len(hs) < 4 || hs[0] != 0x01 {
		return "", false
	}
	body := hs[4:]
	p := 2 + 32
	if p+1 > len(body) {
		return "", false
	}
	sidLen := int(body[p])
	p += 1 + sidLen
	if p+2 > len(body) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2 + csLen
	if p+1 > len(body) {
		return "", false
	}
	compLen := int(body[p])
	p += 1 + compLen
	if p+2 > len(body) {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if p+extTotal > len(body) {
		extTotal = len(body) - p
	}
	ext := body[p : p+extTotal]
	for q := 0; q+4 <= len(ext); {
		etype := binary.BigEndian.Uint16(ext[q:])
		elen := int(binary.BigEndian.Uint16(ext[q+2:]))
		q += 4
		if q+elen > len(ext) {
			break
		}
		if etype == 0x0000 {
			return parseSNIExtension(ext[q : q+elen])
		}
		q += elen
	}
	return "", false
}

// parseSNIExtension reads the first host_name from a server_name extension body.
func parseSNIExtension(d []byte) (string, bool) {
	if len(d) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(d))
	p := 2
	end := p + listLen
	if end > len(d) {
		end = len(d)
	}
	for p+3 <= end {
		nameType := d[p]
		nameLen := int(binary.BigEndian.Uint16(d[p+1:]))
		p += 3
		if p+nameLen > end {
			break
		}
		if nameType == 0x00 { // host_name
			return string(d[p : p+nameLen]), true
		}
		p += nameLen
	}
	return "", false
}

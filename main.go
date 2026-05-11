// decryptor decrypts artifact bundles produced by collector (FCOL0001 / RSA-OAEP + AES-256-GCM).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	magicV1     = "VXMN0001"
	gcmNonceLen = 12
)

func main() {
	keyPath := flag.String("key", "", "RSA private key file (.pri or .pem) (required)")
	inFile := flag.String("in", "", "Single encrypted input file")
	inDir := flag.String("dir", "", "Directory of encrypted files (batch mode)")
	outPath := flag.String("out", "", "Output directory (required)")
	extFlag := flag.String("ext", "", "Extension filter for -dir (default: stem of -key filename)")
	flag.Parse()

	if *keyPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: decryptor -key 2026q2.pri (-in FILE | -dir DIR) -out OUTPUT [-ext EXT]")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if *inFile == "" && *inDir == "" {
		fmt.Fprintln(os.Stderr, "Error: specify -in FILE or -dir DIR")
		os.Exit(1)
	}

	priv, err := loadRSAPrivateKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key: %v\n", err)
		os.Exit(1)
	}

	// Derive the extension filter from the key filename stem when -ext is not set.
	ext := *extFlag
	if ext == "" {
		base := filepath.Base(*keyPath)
		for _, sfx := range []string{".pri", ".pem"} {
			if strings.HasSuffix(strings.ToLower(base), sfx) {
				ext = base[:len(base)-len(sfx)]
				break
			}
		}
		if ext == "" {
			e := filepath.Ext(base)
			if e != "" {
				ext = base[:len(base)-len(e)]
			} else {
				ext = base
			}
		}
	}

	// Open source, decrypt it, and write extracted files under outRoot/<hostname>/.
	decrypt := func(src, outRoot string) error {
		f, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		defer f.Close()

		dec, err := newDecryptor(f, priv)
		if err != nil {
			return fmt.Errorf("init decryptor: %w", err)
		}

		hostname := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
		outDir := filepath.Join(outRoot, hostname)
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
		count, err := dec.decryptArtifacts(outDir)
		if err != nil {
			return err
		}
		fmt.Printf("  ✓ %-40s → %s  (%d files)\n", filepath.Base(src), outDir, count)
		return nil
	}

	if *inDir != "" {
		if err := os.MkdirAll(*outPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create output directory: %v\n", err)
			os.Exit(1)
		}
		entries, err := os.ReadDir(*inDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read %s: %v\n", *inDir, err)
			os.Exit(1)
		}
		total, failed := 0, 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fileExt := strings.TrimPrefix(filepath.Ext(e.Name()), ".")
			if !strings.EqualFold(fileExt, ext) {
				continue
			}
			src := filepath.Join(*inDir, e.Name())
			fmt.Printf("Processing: %s\n", e.Name())
			if err := decrypt(src, *outPath); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ %v\n", err)
				failed++
			}
			total++
		}
		if total == 0 {
			fmt.Printf("[WARN] No *.%s files found in %s\n", ext, *inDir)
		} else {
			fmt.Printf("\n[DONE] %d file(s) processed, %d failed\n", total, failed)
		}
		if failed > 0 {
			os.Exit(1)
		}
	} else {
		if err := os.MkdirAll(*outPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create output path: %v\n", err)
			os.Exit(1)
		}
		if err := decrypt(*inFile, *outPath); err != nil {
			fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
			os.Exit(1)
		}
	}
}

// loadRSAPrivateKey reads a PKCS#1 or PKCS#8 PEM-encoded RSA private key from path.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS8 parse failed: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key (got %T)", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q (expected RSA PRIVATE KEY or PRIVATE KEY)", block.Type)
	}
}

// decryptor holds the stream reader and the initialised AES-256-GCM cipher.
type decryptor struct {
	r   io.Reader
	gcm cipher.AEAD
}

// newDecryptor reads the file header, decrypts the session key with priv, and
// returns a decryptor ready to process the artifact stream.
func newDecryptor(r io.Reader, priv *rsa.PrivateKey) (*decryptor, error) {
	magic := make([]byte, len(magicV1))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != magicV1 {
		return nil, fmt.Errorf("unsupported format magic %q (expected %q)", string(magic), magicV1)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read key length: %w", err)
	}
	encKey := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(r, encKey); err != nil {
		return nil, fmt.Errorf("read encrypted key: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed (wrong key?): %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %w", err)
	}

	return &decryptor{r: r, gcm: gcm}, nil
}

// nextChunk reads and authenticates one GCM chunk; returns nil, nil at end-of-stream.
func (d *decryptor) nextChunk() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(d.r, lenBuf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, nil
		}
		return nil, fmt.Errorf("read chunk length: %w", err)
	}
	ctLen := binary.BigEndian.Uint32(lenBuf[:])
	if ctLen == 0 {
		return nil, nil // end-of-stream marker
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(d.r, ct); err != nil {
		return nil, fmt.Errorf("read chunk ciphertext: %w", err)
	}
	if len(ct) < gcmNonceLen {
		return nil, fmt.Errorf("chunk too short to contain nonce")
	}
	plain, err := d.gcm.Open(nil, ct[:gcmNonceLen], ct[gcmNonceLen:], nil)
	if err != nil {
		return nil, fmt.Errorf("GCM authentication failed (data corrupted or tampered): %w", err)
	}
	return plain, nil
}

// decryptArtifacts reassembles the plaintext stream, extracts named entries into
// outDir, and returns the number of files written.
func (d *decryptor) decryptArtifacts(outDir string) (int, error) {
	var plain []byte
	for {
		chunk, err := d.nextChunk()
		if err != nil {
			return 0, err
		}
		if chunk == nil {
			break
		}
		plain = append(plain, chunk...)
	}

	count := 0
	buf := plain
	for len(buf) > 0 {
		if len(buf) < 12 {
			return count, fmt.Errorf("truncated entry header")
		}
		nameLen := binary.BigEndian.Uint32(buf[0:4])
		dataLen := binary.BigEndian.Uint64(buf[4:12])
		buf = buf[12:]

		if uint64(len(buf)) < uint64(nameLen)+dataLen {
			return count, fmt.Errorf("truncated entry data")
		}
		name := string(buf[:nameLen])
		buf = buf[nameLen:]
		data := buf[:dataLen]
		buf = buf[dataLen:]

		outFile := filepath.Join(outDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(outFile), 0755); err != nil {
			return count, fmt.Errorf("mkdir for %s: %w", name, err)
		}
		if err := os.WriteFile(outFile, data, 0644); err != nil {
			return count, fmt.Errorf("write %s: %w", name, err)
		}
		count++
	}
	return count, nil
}

// Package forensics provides cryptographic hashing for digital evidence integrity.
// Author: Ahmad (https://github.com/cys-dexter)
package forensics

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Hashes contains computed cryptographic checksums.
type Hashes struct {
	SHA256 string `json:"sha256"`
	MD5    string `json:"md5"`
}

// ComputeHashes generates both SHA-256 and MD5 hashes concurrently for in-memory data.
func ComputeHashes(data []byte) Hashes {
	h256 := sha256.New()
	h256.Write(data)
	s256 := hex.EncodeToString(h256.Sum(nil))

	hMD5 := md5.New()
	hMD5.Write(data)
	sMD5 := hex.EncodeToString(hMD5.Sum(nil))

	return Hashes{
		SHA256: s256,
		MD5:    sMD5,
	}
}

// ComputeFileHashes streams an on-disk artifact through SHA-256 and MD5 hash engines.
func ComputeFileHashes(filePath string) (Hashes, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return Hashes{}, fmt.Errorf("unable to open artifact file %s: %w", filePath, err)
	}
	defer file.Close()

	h256 := sha256.New()
	hMD5 := md5.New()

	// MultiWriter routes incoming file stream to both hashers simultaneously
	mw := io.MultiWriter(h256, hMD5)
	if _, err := io.Copy(mw, file); err != nil {
		return Hashes{}, fmt.Errorf("error reading file %s for hashing: %w", filePath, err)
	}

	return Hashes{
		SHA256: hex.EncodeToString(h256.Sum(nil)),
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
	}, nil
}

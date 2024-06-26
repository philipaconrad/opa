package util

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Note(philipc): Originally taken from server/server.go
func ReadMaybeCompressedBody(r *http.Request) (io.ReadCloser, error) {
	fmt.Println("ReadMaybeCompressedBody")
	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		bytesBody, err := io.ReadAll(gzReader)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(bytesBody)), err
	}
	return r.Body, nil
}

func ReadMaybeCompressedBodyBytes(r *http.Request) ([]byte, error) {
	fmt.Println("ReadMaybeCompressedBodyBytes")
	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		// Read out the gzipped body, grab the size trailer field.
		if r.ContentLength > 0 {
			body, _ := io.ReadAll(r.Body)
			slice := body[len(body)-4:]
			var trailer uint32
			err := binary.Read(bytes.NewReader(slice), binary.LittleEndian, &trailer)
			if err != nil {
				panic(err)
			}
			fmt.Printf("b:%d, sl:%d, sl:%v, value:%v\n", len(body), len(slice), slice, trailer)
		}
		gzReader, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		bytesBody, err := io.ReadAll(gzReader)
		if err != nil {
			return nil, err
		}
		return bytesBody, err
	}
	// Uncompressed, known content-length path:
	if r.ContentLength > 0 {
		buf := make([]byte, r.ContentLength)
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	// Uncompressed, unknown content-length path:
	return io.ReadAll(r.Body)
}

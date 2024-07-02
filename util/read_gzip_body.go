package util

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
)

type requestBodyContextKey string

const reqBodyCtxKey = requestBodyContextKey("request-body-context-key")

// Note(philipc): Originally taken from server/server.go
// The CompressHandler handles validating that the gzip payload is within the
// allowed max size limit. Thus, in the event of a forged payload size trailer,
// the worst that can happen is that we waste memory up to the allowed max gzip
// payload size, but not an unbounded amount of memory, as was potentially
// possible before.
func ReadMaybeCompressedBody(r *http.Request) (context.Context, []byte, error) {
	ctx := r.Context()
	if body, ok := ctx.Value(reqBodyCtxKey).([]byte); ok {
		return ctx, body, nil
	}
	if r.ContentLength <= 0 {
		return ctx, []byte{}, nil
	}
	// Read content from the request body into a buffer of known size.
	content := bytes.NewBuffer(make([]byte, 0, r.ContentLength))
	if _, err := io.CopyN(content, r.Body, r.ContentLength); err != nil {
		return ctx, content.Bytes(), err
	}

	// Decompress gzip content by reading from the buffer.
	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		// Note(philipc): The last 4 bytes of a well-formed gzip blob will
		// always be a little-endian uint32, representing the decompressed
		// content size, modulo 2^32. We validate that the size is safe,
		// earlier in CompressHandler.
		sizeTrailerField := binary.LittleEndian.Uint32(content.Bytes()[content.Len()-4:])
		gzReader, err := gzip.NewReader(content)
		if err != nil {
			return ctx, nil, err
		}
		defer gzReader.Close()
		decompressedContent := bytes.NewBuffer(make([]byte, 0, sizeTrailerField))
		if _, err := io.CopyN(decompressedContent, gzReader, int64(sizeTrailerField)); err != nil {
			return ctx, decompressedContent.Bytes(), err
		}
		ctx = context.WithValue(ctx, reqBodyCtxKey, decompressedContent.Bytes())
		return ctx, decompressedContent.Bytes(), nil
	}

	// Request was not compressed; return the content bytes.
	ctx = context.WithValue(ctx, reqBodyCtxKey, content.Bytes())
	return ctx, content.Bytes(), nil
}

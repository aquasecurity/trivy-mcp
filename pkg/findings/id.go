package findings

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"strconv"
)

func MakeFindingID(src, identifier, artifactType, name, version, path string, line int) string {
	h := sha1.New()
	_, _ = io.WriteString(h, src)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, identifier)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, artifactType)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, name)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, version)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, path)
	_, _ = io.WriteString(h, "|")
	_, _ = io.WriteString(h, strconv.Itoa(line))
	return hex.EncodeToString(h.Sum(nil))[:16] // short, but stable
}

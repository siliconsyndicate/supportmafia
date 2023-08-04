package util

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/skip2/go-qrcode"
)

// GetQRCodeAsBase64 return qr code as base64 encoding
func GetQRCodeAsBase64(content string) (*string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	q.DisableBorder = true
	im := q.Image(600)
	buf := new(bytes.Buffer)
	if err := png.Encode(buf, im); err != nil {
		return nil, err
	}
	imageBit := buf.Bytes()
	imgBase64Str := base64.StdEncoding.EncodeToString([]byte(imageBit))
	return &imgBase64Str, err
}

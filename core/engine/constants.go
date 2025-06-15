package engine

import (
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

// TLSVersionMap maps string representations to tls.Version constants.
var TLSVersionMap = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

// UTLSHelloIDMap maps string representations to utls.ClientHelloID.
var UTLSHelloIDMap = map[string]utls.ClientHelloID{
	"HelloChrome_Auto":       utls.HelloChrome_Auto,
	"HelloFirefox_Auto":      utls.HelloFirefox_Auto,
	"HelloIOS_Auto":          utls.HelloIOS_Auto,
	"HelloAndroid_11_OkHttp": utls.HelloAndroid_11_OkHttp,
	"HelloEdge_Auto":         utls.HelloEdge_Auto,
	"HelloSafari_Auto":       utls.HelloSafari_Auto,
	"Hello360_Auto":          utls.Hello360_Auto,
	"HelloQQ_Auto":           utls.HelloQQ_Auto,
	"HelloRandomized":        utls.HelloRandomized,
	"HelloRandomizedALPN":    utls.HelloRandomizedALPN,
	"HelloRandomizedNoALPN":  utls.HelloRandomizedNoALPN,
}

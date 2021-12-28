package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/smartwalle/alipay/v3"
	"github.com/smartwalle/crypto4go"
)

func main() {
	var dataFile = flag.String("data-file", "", "原始数据(文件)")
	var pubKeyFile = flag.String("pubkey-file", "", "支付宝公钥文件")
	flag.Parse()

	httpForm := readHttpForm(*dataFile)
	appId := httpForm.Get("app_id")
	log.Printf("app_id: %s", appId)

	pubKey, err := LoadAliPayPublicKeyFromFile(*pubKeyFile)
	panicIf(err)
	ok, err := alipay.VerifySign(httpForm, pubKey)
	log.Printf("verify_sign: %v  err:%v", ok, err)
}

func panicIf(err error) {
	if err != nil {
		panic(err)
	}
}

func readHttpForm(fpath string) url.Values {
	data, err := os.ReadFile(fpath)
	panicIf(err)

	data2 := strings.Trim(string(data), "\r\n \t")
	params, err := url.ParseQuery(data2)
	panicIf(err)
	return params
}

func LoadAliPayPublicKeyFromFile(fpath string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(fpath)
	if err != nil {
		return nil, fmt.Errorf("load alipay-publicKey failed: %w", err)
	}
	data2 := strings.Trim(string(data), "\r\n \t")
	return LoadAliPayPublicKey2(data2)
}

func LoadAliPayPublicKey(data []byte) (*rsa.PublicKey, error) {
	cert, err := crypto4go.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("load alipay-publicKey failed: %w", err)
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if key == nil || !ok {
		return nil, fmt.Errorf("load alipay-publicKey failed")
	}
	return key, nil
}

func LoadAliPayPublicKey2(data string) (*rsa.PublicKey, error) {
	pub, err := crypto4go.ParsePublicKey(crypto4go.FormatPublicKey(data))
	if err != nil {
		return nil, fmt.Errorf("load alipay-publicKey failed: %w", err)
	}
	return pub, nil
}

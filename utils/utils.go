package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var DNS_WEB_ADDRESS string // example: dnslog:8921
var DNS_AUTH_TOKEN string
var DNS_LOG_DOMAIN string

func init() {
	rand.Seed(time.Now().UnixNano())
}

func Setup(dnsWebAddress string, dnsAuthToken string, dnsLogDomain string) {
	DNS_WEB_ADDRESS = dnsWebAddress
	DNS_AUTH_TOKEN = dnsAuthToken
	DNS_LOG_DOMAIN = dnsLogDomain
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// 获取md5字符串
func Md5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func IsExistDNSLog(logStr string) bool {
	targeUrl := "http://" + DNS_WEB_ADDRESS + "/api/verifyDns"

	//json序列化
	post := "{\"Query\":\"" + logStr + "." + DNS_LOG_DOMAIN + "\"}"

	var jsonStr = []byte(post)

	req, err := http.NewRequest("POST", targeUrl, bytes.NewBuffer(jsonStr))

	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("token", DNS_AUTH_TOKEN)

	client := &http.Client{}
	resp, err := client.Do(req)

	defer func() {
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.Body == nil {
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println("response Status:", resp.Status)
	//fmt.Println("response Headers:", resp.Header)
	//fmt.Println("response Headers:", string(body))

	if strings.Contains(string(body), "true") {
		return true
	} else {
		return false
	}
}

// 获取host
func GetHostFromUrl(targetUrl string) string {
	u, err := url.Parse(targetUrl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

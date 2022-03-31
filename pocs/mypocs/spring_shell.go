package mypocs

import (
	"fmt"
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	util "github.com/deenrookie/kunpeng-plus/utils"
	"net/http"
	"strings"
)

type springShell struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("spring", &springShell{})
}

func (d *springShell) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "spring shell",
		Remarks: "spring shell error test",
		Level:   0,
		Type:    "RCE",
		Author:  "Anonymous",
		References: plugin.References{
			URL:  "",
			CVE:  "",
			KPID: "KP-1005",
		},
	}
	return d.info
}

func (d *springShell) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *springShell) Check(URL string, meta plugin.TaskMeta) bool {
	_ = meta
	var request *http.Request
	fullPayload := fmt.Sprintf("?class.module.classLoader[0]=test")
	request, _ = http.NewRequest("GET", URL+"/"+fullPayload, nil)
	resp, err := util.RequestDo(request, false)

	// 存在腾讯门神防火墙或者华为防火墙的情况下执行return false
	if &resp != nil && err == nil {
		if resp.Other != nil {
			if resp.Other.StatusCode == 501 || resp.Other.StatusCode == 418 ||
				strings.Contains(string(resp.Body), "WAF") ||
				strings.Contains(string(resp.Body), "防火墙") {
				return false
			}
		}

		if resp.Other.StatusCode == 500 || resp.Other.StatusCode == 400 {
			if strings.Contains(string(resp.Body), "400 No required SSL certificate") {
				return false
			}

			if strings.Contains(string(resp.Body), "springframework") || strings.Contains(string(resp.Body), "full stack") {
				result := d.info
				result.Response = "TEST"
				result.Request = "TEST"
				d.result = append(d.result, result)
				return true
			}
		}
	} else if err != nil {
	}

	return false
}

package mypocs

import (
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	util "github.com/deenrookie/kunpeng-plus/utils"
	"net/http"
	"strings"
)

type vmware954RCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("vmware", &vmware954RCE{})
}

func (d *vmware954RCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "vmware",
		Remarks: "vmware rce",
		Level:   0,
		Type:    "RCE",
		Author:  "Deen",
		References: plugin.References{
			URL:  "",
			CVE:  "",
			KPID: "KP-1006",
		},
	}
	return d.info
}

func (d *vmware954RCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *vmware954RCE) Check(URL string, meta plugin.TaskMeta) bool {
	_ = meta

	domain := util.GetHostFromUrl(URL)
	if domain == "" {
		return false
	}
	var request *http.Request

	request, _ = http.NewRequest("GET", URL+"/catalog-portal/ui/oauth/verify", nil)
	resp, err := util.RequestDo(request, false)
	if &resp != nil && err == nil {
		if resp.Other != nil {
			if strings.Contains(string(resp.Body), "server.unexpected.error") {
				result := d.info
				result.Response = string(resp.Body)
				result.Request = "TEST"
				d.result = append(d.result, result)
				return true
			}
		}
	}
	return false
}

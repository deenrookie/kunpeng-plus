package mypocs

import (
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	util "github.com/deenrookie/kunpeng-plus/utils"
	"net/http"
)

type springCloudGateWayRCE struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("spring_cloud_gateway", &springCloudGateWayRCE{})
}

func (d *springCloudGateWayRCE) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "spring cloud gate way",
		Remarks: "spring cloud gate way rce",
		Level:   0,
		Type:    "RCE",
		Author:  "Deen",
		References: plugin.References{
			URL:  "https://twitter.com/wdahlenb/status/1473050822367924224",
			CVE:  "",
			KPID: "KP-1004",
		},
	}
	return d.info
}

func (d *springCloudGateWayRCE) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *springCloudGateWayRCE) Check(URL string, meta plugin.TaskMeta) bool {
	_ = meta

	domain := util.GetHostFromUrl(URL)
	if domain == "" {
		return false
	}
	var request *http.Request

	request, _ = http.NewRequest("GET", URL+"/actuator/gateway/routes", nil)
	resp, err := util.RequestDo(request, false)
	if &resp != nil && err == nil {
		if resp.Other != nil {
			if resp.Other.StatusCode == 200 {
				return true
			}
		}
	}
	return false
}

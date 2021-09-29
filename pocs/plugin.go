package pocs

// GoPlugins GO插件集
var GoPlugins map[string][]GoPlugin

//References 插件附加信息
type References struct {
	URL  string `json:"url"`
	CVE  string `json:"cve"`
	KPID string `json:"kpid"`
}

// Plugin 漏洞插件信息
type Plugin struct {
	Name       string     `json:"name"`
	Remarks    string     `json:"remarks"`
	Level      int        `json:"level"`
	Type       string     `json:"type"`
	Author     string     `json:"author"`
	References References `json:"references"`
	Request    string
	Response   string
}

// GoPlugin 插件接口
type GoPlugin interface {
	Init() Plugin
	Check(netloc string, meta TaskMeta) bool
	GetResult() []Plugin
}

// TaskMeta 任务额外信息
type TaskMeta struct {
	System   string   `json:"system"`
	PathList []string `json:"pathlist"`
	FileList []string `json:"filelist"`
	PassList []string `json:"passlist"`
}

// Regist 注册插件
func Regist(target string, plugin GoPlugin) {
	GoPlugins[target] = append(GoPlugins[target], plugin)
	// var pluginInfo = plugin.Init()
	// util.Logger.Println("init plugin:", pluginInfo.References.KPID, pluginInfo.Name)
}



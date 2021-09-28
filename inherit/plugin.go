package inherit

import (
	"fmt"
	"github.com/opensec-cn/kunpeng/plugin"
	_ "github.com/opensec-cn/kunpeng/plugin/go"
)

func A() {
	fmt.Println(plugin.GoPlugins)
}

package mypocs

import (
	plugin "github.com/deenrookie/kunpeng-plus/pocs"
	"testing"
)

func TestScan(t *testing.T) {
	a := nextVersion{}
	a.Check("http://192.168.31.95:3000/", plugin.TaskMeta{})

	//scanRCE("http://192.168.31.95:3000")
	//scanSSRFpoc("http://192.168.31.95:3000")
}

package mypocs

import "testing"

func TestScan(t *testing.T) {
	scanRCE("http://192.168.31.95:3000")
}

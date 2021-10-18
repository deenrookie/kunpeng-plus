package main

import (
	"github.com/deenrookie/kunpeng-plus/db"
)

func main(){
	db.Init("")
	db.SyncToDB()
}


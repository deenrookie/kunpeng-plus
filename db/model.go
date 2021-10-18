package db

import (
	"github.com/deenrookie/kunpeng-plus/pocs"
	_ "github.com/deenrookie/kunpeng-plus/pocs/go"
)

type Poc struct {
	Id           int    `json:"id"`
	Level        int    `json:"level"`
	Name         string `json:"name"`
	Remarks      string `json:"remarks"`
	Tag          string `json:"tag"`
	Type         string `json:"type"`
	Author       string `json:"author"`
	ReferenceUrl string `json:"reference_url"`
	ReferenceCVE string `json:"reference_cve"`
}

// 第一次使用，创建表
func AutoMigrate() {
	err := DB.Set("gorm:table_options", "ENGINE=InnoDB").AutoMigrate(&Poc{})
	if err != nil {
		panic(err)
	}
}

// 将poc的数据同步到数据库
func SyncToDB() {
	dbPocs := make([]Poc, 0)
	for tag, item := range pocs.GoPlugins {
		for _, poc := range item {
			newPoc := Poc{
				Id:           0,
				Level:        poc.Init().Level,
				Name:         poc.Init().Name,
				Remarks:      poc.Init().Remarks,
				Tag:          tag,
				Type:         poc.Init().Type,
				Author:       poc.Init().Author,
				ReferenceUrl: poc.Init().References.URL,
				ReferenceCVE: poc.Init().References.CVE,
			}
			dbPocs = append(dbPocs, newPoc)
		}
	}
	DB.Create(&dbPocs)
}
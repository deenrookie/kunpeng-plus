package db

import (
	"fmt"
	"github.com/deenrookie/kunpeng-plus/pocs"
	_ "github.com/deenrookie/kunpeng-plus/pocs/go"
	"github.com/deenrookie/kunpeng-plus/utils"
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
	Hash         string `json:"hash"`
}

// 第一次使用，创建表
func AutoMigrate() {
	if DB.Migrator().HasTable("pocs") {
		return
	}
	err := DB.Set("gorm:table_options", "ENGINE=InnoDB").AutoMigrate(&Poc{})
	if err != nil {
		panic(err)
	}
}

// 初次，将poc的数据同步到数据库
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
			newPoc.Hash = utils.Md5(fmt.Sprintf(newPoc.Name, newPoc.Remarks, newPoc.Author, newPoc.ReferenceCVE, newPoc.ReferenceUrl))
			if !isPocExist(newPoc.Hash) {
				dbPocs = append(dbPocs, newPoc)
			}
		}
	}
	if len(dbPocs) > 0 {
		DB.Create(&dbPocs)
	}
}

// 判断poc是否同步到数据库
func isPocExist(hash string) bool {
	pocModel := &Poc{}
	DB.Table("pocs").Where("hash = ?", hash).Find(pocModel)
	if pocModel.Id != 0 {
		return true
	}
	return false
}

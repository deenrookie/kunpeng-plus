package db

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"time"
)

var DB *gorm.DB

func init() {
	Database("")
}

func Database(conn string) {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second, // Slow SQL threshold
			LogLevel:                  logger.Info, // Log level
			IgnoreRecordNotFoundError: true,        // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,       // Disable color
		},
	)

	db, err := gorm.Open(mysql.Open(conn), &gorm.Config{
		Logger: newLogger,
	})

	if conn == "" || err != nil {
		panic(err)
	}
	if db != nil {
		sqlDb, err := db.DB()
		if err != nil {
			panic(err)
		}
		if sqlDb != nil {
			sqlDb.SetMaxIdleConns(10)
			sqlDb.SetMaxOpenConns(20)
			DB = db
		}
	}
}



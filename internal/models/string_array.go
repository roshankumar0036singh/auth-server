package models

import (
	"database/sql/driver"

	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	return pq.StringArray(a).Value()
}

func (a *StringArray) Scan(value interface{}) error {
	var scopes pq.StringArray
	if err := scopes.Scan(value); err != nil {
		return err
	}
	*a = StringArray(scopes)
	return nil
}

func (StringArray) GormDataType() string {
	return "stringArray"
}

func (StringArray) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	if db.Dialector.Name() == "postgres" {
		return "text[]"
	}
	return "text"
}

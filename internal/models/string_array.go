package models

import (
	"context"
	"database/sql/driver"
	"encoding/json"

	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	data, err := json.Marshal([]string(a))
	if err != nil {
		return nil, err
	}
	return string(data), nil
}

func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	var raw []byte
	switch v := value.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		var scopes pq.StringArray
		if err := scopes.Scan(value); err != nil {
			return err
		}
		*a = StringArray(scopes)
		return nil
	}

	var values []string
	if err := json.Unmarshal(raw, &values); err == nil {
		*a = StringArray(values)
		return nil
	}

	var scopes pq.StringArray
	if err := scopes.Scan(string(raw)); err != nil {
		return err
	}

	*a = StringArray(scopes)
	return nil
}

func (a StringArray) GormValue(_ context.Context, db *gorm.DB) clause.Expr {
	if db.Dialector.Name() == "postgres" {
		value, _ := pq.StringArray(a).Value()
		return clause.Expr{SQL: "?", Vars: []interface{}{value}}
	}

	value, _ := a.Value()
	return clause.Expr{SQL: "?", Vars: []interface{}{value}}
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

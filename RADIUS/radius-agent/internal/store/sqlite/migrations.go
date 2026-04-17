package sqlite

import _ "embed"

//go:embed schema.sql
var migration001 string

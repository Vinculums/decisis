// Package ui renders the shop pages.
package ui // import "example.com/shop/svc/internal/ui"

import "example.com/shop/svc/internal/db"

import (
	"fmt"
	m "example.com/shop/svc/internal/db/models"
	. "example.com/shop/svc/internal/api"
	_ "example.com/shop/svc/internal/db/driver"
	"example.com/shop/svc/internal/gone"
	"github.com/lib/pq"
)

/* import "example.com/shop/svc/internal/db/secret" */
var query = `import "example.com/shop/svc/internal/db/raw"`
var quote = '"'

func View() string { return fmt.Sprint(db.Name, m.Order{}, Client{}, gone.X, pq.Y, query, quote) }

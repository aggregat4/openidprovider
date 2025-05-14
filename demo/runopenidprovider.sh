#!/bin/sh
rm -f demodb.*
rm -f demo-private.pem demo-public.pem

go run ../cmd/createkey/main.go --private demo-private.pem --public demo-public.pem
go run ../cmd/createuser/main.go --db demodb --username testuser --password testpassword
go run ../cmd/server/main.go --config demo-openidprovider-config.json
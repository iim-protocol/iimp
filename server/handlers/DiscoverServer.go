package handlers

import (
	"net/http"

	"github.com/iim-protocol/iimp/server/config"
	"github.com/iim-protocol/iimp/server/iimpserver"
)

func DiscoverServer(w http.ResponseWriter, r *http.Request) {
	iimpserver.WriteDiscoverServer200Response(w, iimpserver.DiscoverServer200Response{
		Body: iimpserver.DiscoverServer200ResponseBody{
			Domain:  config.C.Domain,
			Version: iimpserver.IIMPVersion,
		},
	})
}

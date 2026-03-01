package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/iim-protocol/iimp/server/iimpserver"
)

func RegisterHandlers(r *chi.Mux) {
	// Discovery Endpoints
	r.HandleFunc(
		iimpserver.GetJWKSStoreRequestRoutePath,
		withMethod(
			GetJWKSStore,
			iimpserver.GetJWKSStoreRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.DiscoverServerRequestRoutePath,
		withMethod(
			DiscoverServer,
			iimpserver.DiscoverServerRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.GetUserPublicKeyRequestRoutePath,
		withMethod(
			GetUserPublicKey,
			iimpserver.GetUserPublicKeyRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.GetUserPublicKeyByIdRequestRoutePath,
		withMethod(
			GetUserPublicKeyById,
			iimpserver.GetUserPublicKeyByIdRequestHTTPMethod,
		),
	)

	// Client Endpoints

	// Auth endpoints
	r.HandleFunc(
		iimpserver.SignUpRequestRoutePath,
		withMethod(
			SignUp,
			iimpserver.SignUpRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.LoginRequestRoutePath,
		withMethod(
			Login,
			iimpserver.LoginRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.LogoutRequestRoutePath,
		withMethod(
			Logout,
			iimpserver.LogoutRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.RefreshSessionRequestRoutePath,
		withMethod(
			RefreshSession,
			iimpserver.RefreshSessionRequestHTTPMethod,
		),
	)

	// TODO: implement password reset later
}

func withMethod(handler http.HandlerFunc, allowedMethod string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != allowedMethod {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

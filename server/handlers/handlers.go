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

	// Public key management endpoints
	r.HandleFunc(
		iimpserver.AddPublicKeyRequestRoutePath,
		withMethod(
			AddPublicKey,
			iimpserver.AddPublicKeyRequestHTTPMethod,
		),
	)

	// Conversation Endpoints
	r.HandleFunc(
		iimpserver.NewConversationRequestRoutePath,
		withMethod(
			NewConversation,
			iimpserver.NewConversationRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.UpdateConversationRequestRoutePath,
		withMethod(
			UpdateConversation,
			iimpserver.UpdateConversationRequestHTTPMethod,
		),
	)

	// Message Endpoints
	r.HandleFunc(
		iimpserver.NewMessageRequestRoutePath,
		withMethod(
			NewMessage,
			iimpserver.NewMessageRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.EditMessageRequestRoutePath,
		withMethod(
			EditMessage,
			iimpserver.EditMessageRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.RedactMessageRequestRoutePath,
		withMethod(
			RedactMessage,
			iimpserver.RedactMessageRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.ReadMessageRequestRoutePath,
		withMethod(
			ReadMessage,
			iimpserver.ReadMessageRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.ReactToMessageRequestRoutePath,
		withMethod(
			ReactToMessage,
			iimpserver.ReactToMessageRequestHTTPMethod,
		),
	)

	// Attachment Endpoints
	r.HandleFunc(
		iimpserver.UploadAttachmentRequestRoutePath,
		withMethod(
			UploadAttachment,
			iimpserver.UploadAttachmentRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.DownloadAttachmentRequestRoutePath,
		withMethod(
			DownloadAttachment,
			iimpserver.DownloadAttachmentRequestHTTPMethod,
		),
	)

	// User events pull endpoint
	r.HandleFunc(
		iimpserver.PullUserEventsRequestRoutePath,
		withMethod(
			PullUserEvents,
			iimpserver.PullUserEventsRequestHTTPMethod,
		),
	)

	// Federation endpoints
	r.HandleFunc(
		iimpserver.ConversationFederationRequestRoutePath,
		withMethod(
			ConversationFederation,
			iimpserver.ConversationFederationRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.MessageFederationRequestRoutePath,
		withMethod(
			MessageFederation,
			iimpserver.MessageFederationRequestHTTPMethod,
		),
	)

	r.HandleFunc(
		iimpserver.GetUserInfoFederationRequestRoutePath,
		withMethod(
			GetUserInfoFederation,
			iimpserver.GetUserInfoFederationRequestHTTPMethod,
		),
	)
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

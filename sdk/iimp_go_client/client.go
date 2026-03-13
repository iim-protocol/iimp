package iimp_go_client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type IIMP struct {
	baseURL string
	client  *http.Client
}

func NewIIMP(baseURL string) *IIMP {
	return &IIMP{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func NewIIMPWithClient(baseURL string, client *http.Client) *IIMP {
	return &IIMP{
		baseURL: baseURL,
		client:  client,
	}
}

func (c *IIMP) do(request *http.Request) (*http.Response, error) {
	if request.Header.Get("Accept") == "" {
		request.Header.Set("Accept", "application/json")
	}
	request.Header.Set("User-Agent", "IIMP-GoSDK/")
	return c.client.Do(request)
}

type AddPublicKeyResult struct {
	StatusCode int

	Response201 AddPublicKey201Response

	Response400 AddPublicKey400Response

	Response401 AddPublicKey401Response

	Response500 AddPublicKey500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) AddPublicKey(ctx context.Context, params AddPublicKeyRequest) (AddPublicKeyResult, error) {
	if err := params.Validate(); err != nil {
		return AddPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return AddPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/keys"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return AddPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return AddPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return AddPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := AddPublicKeyResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 201:
		result, err := NewAddPublicKey201Response(resp)
		if err != nil {
			return AddPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response201 = result
		return response, nil

	case 400:
		result, err := NewAddPublicKey400Response(resp)
		if err != nil {
			return AddPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewAddPublicKey401Response(resp)
		if err != nil {
			return AddPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewAddPublicKey500Response(resp)
		if err != nil {
			return AddPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type ConversationFederationResult struct {
	StatusCode int

	Response200 ConversationFederation200Response

	Response400 ConversationFederation400Response

	Response401 ConversationFederation401Response

	Response403 ConversationFederation403Response

	Response404 ConversationFederation404Response

	Response500 ConversationFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) ConversationFederation(ctx context.Context, params ConversationFederationRequest) (ConversationFederationResult, error) {
	if err := params.Validate(); err != nil {
		return ConversationFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return ConversationFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/federation/conversations"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return ConversationFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return ConversationFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return ConversationFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := ConversationFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewConversationFederation200Response(resp)
		if err != nil {
			return ConversationFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewConversationFederation400Response(resp)
		if err != nil {
			return ConversationFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewConversationFederation401Response(resp)
		if err != nil {
			return ConversationFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewConversationFederation403Response(resp)
		if err != nil {
			return ConversationFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewConversationFederation404Response(resp)
		if err != nil {
			return ConversationFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewConversationFederation500Response(resp)
		if err != nil {
			return ConversationFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type DiscoverServerResult struct {
	StatusCode int

	Response200 DiscoverServer200Response

	Response404 DiscoverServer404Response

	Response500 DiscoverServer500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) DiscoverServer(ctx context.Context, params DiscoverServerRequest) (DiscoverServerResult, error) {
	if err := params.Validate(); err != nil {
		return DiscoverServerResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/.well-known/iimp"

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return DiscoverServerResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	resp, err := c.do(req)
	if err != nil {
		return DiscoverServerResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := DiscoverServerResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewDiscoverServer200Response(resp)
		if err != nil {
			return DiscoverServerResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 404:
		result, err := NewDiscoverServer404Response(resp)
		if err != nil {
			return DiscoverServerResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewDiscoverServer500Response(resp)
		if err != nil {
			return DiscoverServerResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type DownloadAttachmentResult struct {
	StatusCode int

	Response200 DownloadAttachment200Response

	Response400 DownloadAttachment400Response

	Response401 DownloadAttachment401Response

	Response403 DownloadAttachment403Response

	Response404 DownloadAttachment404Response

	Response500 DownloadAttachment500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) DownloadAttachment(ctx context.Context, params DownloadAttachmentRequest) (DownloadAttachmentResult, error) {
	if err := params.Validate(); err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/attachments/{fileId}/bytes"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	pathParamFileId, err := paramToString(params.FileId, "path parameter: FileId", "string", true)
	if err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: fileId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{fileId}", fmt.Sprintf("%v", pathParamFileId))

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return DownloadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := DownloadAttachmentResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewDownloadAttachment200Response(resp)
		if err != nil {
			return DownloadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewDownloadAttachment400Response(resp)
		if err != nil {
			return DownloadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewDownloadAttachment401Response(resp)
		if err != nil {
			return DownloadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewDownloadAttachment403Response(resp)
		if err != nil {
			return DownloadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewDownloadAttachment404Response(resp)
		if err != nil {
			return DownloadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewDownloadAttachment500Response(resp)
		if err != nil {
			return DownloadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type EditMessageResult struct {
	StatusCode int

	Response200 EditMessage200Response

	Response400 EditMessage400Response

	Response401 EditMessage401Response

	Response403 EditMessage403Response

	Response404 EditMessage404Response

	Response500 EditMessage500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) EditMessage(ctx context.Context, params EditMessageRequest) (EditMessageResult, error) {
	if err := params.Validate(); err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/conversations/{conversationId}/messages/{messageId}"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	req, err := http.NewRequestWithContext(
		ctx,
		"PUT",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return EditMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := EditMessageResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewEditMessage200Response(resp)
		if err != nil {
			return EditMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewEditMessage400Response(resp)
		if err != nil {
			return EditMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewEditMessage401Response(resp)
		if err != nil {
			return EditMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewEditMessage403Response(resp)
		if err != nil {
			return EditMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewEditMessage404Response(resp)
		if err != nil {
			return EditMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewEditMessage500Response(resp)
		if err != nil {
			return EditMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type GetJWKSStoreResult struct {
	StatusCode int

	Response200 GetJWKSStore200Response

	Response500 GetJWKSStore500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) GetJWKSStore(ctx context.Context, params GetJWKSStoreRequest) (GetJWKSStoreResult, error) {
	if err := params.Validate(); err != nil {
		return GetJWKSStoreResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/.well-known/iimp/jwks"

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return GetJWKSStoreResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	resp, err := c.do(req)
	if err != nil {
		return GetJWKSStoreResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := GetJWKSStoreResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewGetJWKSStore200Response(resp)
		if err != nil {
			return GetJWKSStoreResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 500:
		result, err := NewGetJWKSStore500Response(resp)
		if err != nil {
			return GetJWKSStoreResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type GetUserInfoFederationResult struct {
	StatusCode int

	Response200 GetUserInfoFederation200Response

	Response400 GetUserInfoFederation400Response

	Response401 GetUserInfoFederation401Response

	Response404 GetUserInfoFederation404Response

	Response500 GetUserInfoFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) GetUserInfoFederation(ctx context.Context, params GetUserInfoFederationRequest) (GetUserInfoFederationResult, error) {
	if err := params.Validate(); err != nil {
		return GetUserInfoFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/federation/users/{userId}"

	pathParamUserId, err := paramToString(params.UserId, "path parameter: UserId", "string", true)
	if err != nil {
		return GetUserInfoFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: userId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{userId}", fmt.Sprintf("%v", pathParamUserId))

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return GetUserInfoFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return GetUserInfoFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return GetUserInfoFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := GetUserInfoFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewGetUserInfoFederation200Response(resp)
		if err != nil {
			return GetUserInfoFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewGetUserInfoFederation400Response(resp)
		if err != nil {
			return GetUserInfoFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewGetUserInfoFederation401Response(resp)
		if err != nil {
			return GetUserInfoFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 404:
		result, err := NewGetUserInfoFederation404Response(resp)
		if err != nil {
			return GetUserInfoFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewGetUserInfoFederation500Response(resp)
		if err != nil {
			return GetUserInfoFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type GetUserPublicKeyResult struct {
	StatusCode int

	Response200 GetUserPublicKey200Response

	Response400 GetUserPublicKey400Response

	Response404 GetUserPublicKey404Response

	Response500 GetUserPublicKey500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) GetUserPublicKey(ctx context.Context, params GetUserPublicKeyRequest) (GetUserPublicKeyResult, error) {
	if err := params.Validate(); err != nil {
		return GetUserPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/.well-known/iimp/keys/users/{userId}"

	pathParamUserId, err := paramToString(params.UserId, "path parameter: UserId", "string", true)
	if err != nil {
		return GetUserPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: userId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{userId}", fmt.Sprintf("%v", pathParamUserId))

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return GetUserPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	resp, err := c.do(req)
	if err != nil {
		return GetUserPublicKeyResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := GetUserPublicKeyResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewGetUserPublicKey200Response(resp)
		if err != nil {
			return GetUserPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewGetUserPublicKey400Response(resp)
		if err != nil {
			return GetUserPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 404:
		result, err := NewGetUserPublicKey404Response(resp)
		if err != nil {
			return GetUserPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewGetUserPublicKey500Response(resp)
		if err != nil {
			return GetUserPublicKeyResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type GetUserPublicKeyByIdResult struct {
	StatusCode int

	Response200 GetUserPublicKeyById200Response

	Response400 GetUserPublicKeyById400Response

	Response404 GetUserPublicKeyById404Response

	Response500 GetUserPublicKeyById500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) GetUserPublicKeyById(ctx context.Context, params GetUserPublicKeyByIdRequest) (GetUserPublicKeyByIdResult, error) {
	if err := params.Validate(); err != nil {
		return GetUserPublicKeyByIdResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/.well-known/iimp/keys/users/{userId}/{keyId}"

	pathParamUserId, err := paramToString(params.UserId, "path parameter: UserId", "string", true)
	if err != nil {
		return GetUserPublicKeyByIdResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: userId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{userId}", fmt.Sprintf("%v", pathParamUserId))

	pathParamKeyId, err := paramToString(params.KeyId, "path parameter: KeyId", "string", true)
	if err != nil {
		return GetUserPublicKeyByIdResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: keyId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{keyId}", fmt.Sprintf("%v", pathParamKeyId))

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return GetUserPublicKeyByIdResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	resp, err := c.do(req)
	if err != nil {
		return GetUserPublicKeyByIdResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := GetUserPublicKeyByIdResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewGetUserPublicKeyById200Response(resp)
		if err != nil {
			return GetUserPublicKeyByIdResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewGetUserPublicKeyById400Response(resp)
		if err != nil {
			return GetUserPublicKeyByIdResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 404:
		result, err := NewGetUserPublicKeyById404Response(resp)
		if err != nil {
			return GetUserPublicKeyByIdResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewGetUserPublicKeyById500Response(resp)
		if err != nil {
			return GetUserPublicKeyByIdResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type LoginResult struct {
	StatusCode int

	Response200 Login200Response

	Response400 Login400Response

	Response401 Login401Response

	Response500 Login500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) Login(ctx context.Context, params LoginRequest) (LoginResult, error) {
	if err := params.Validate(); err != nil {
		return LoginResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return LoginResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/login"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return LoginResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return LoginResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := LoginResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewLogin200Response(resp)
		if err != nil {
			return LoginResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewLogin400Response(resp)
		if err != nil {
			return LoginResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewLogin401Response(resp)
		if err != nil {
			return LoginResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewLogin500Response(resp)
		if err != nil {
			return LoginResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type LogoutResult struct {
	StatusCode int

	Response204 Logout204Response

	Response400 Logout400Response

	Response401 Logout401Response

	Response500 Logout500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) Logout(ctx context.Context, params LogoutRequest) (LogoutResult, error) {
	if err := params.Validate(); err != nil {
		return LogoutResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/client/logout"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return LogoutResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return LogoutResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return LogoutResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := LogoutResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 204:
		result, err := NewLogout204Response(resp)
		if err != nil {
			return LogoutResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response204 = result
		return response, nil

	case 400:
		result, err := NewLogout400Response(resp)
		if err != nil {
			return LogoutResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewLogout401Response(resp)
		if err != nil {
			return LogoutResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewLogout500Response(resp)
		if err != nil {
			return LogoutResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type MessageFederationResult struct {
	StatusCode int

	Response200 MessageFederation200Response

	Response400 MessageFederation400Response

	Response401 MessageFederation401Response

	Response403 MessageFederation403Response

	Response404 MessageFederation404Response

	Response500 MessageFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) MessageFederation(ctx context.Context, params MessageFederationRequest) (MessageFederationResult, error) {
	if err := params.Validate(); err != nil {
		return MessageFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return MessageFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/federation/conversations/{conversationId}/messages"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return MessageFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return MessageFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return MessageFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return MessageFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := MessageFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewMessageFederation200Response(resp)
		if err != nil {
			return MessageFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewMessageFederation400Response(resp)
		if err != nil {
			return MessageFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewMessageFederation401Response(resp)
		if err != nil {
			return MessageFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewMessageFederation403Response(resp)
		if err != nil {
			return MessageFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewMessageFederation404Response(resp)
		if err != nil {
			return MessageFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewMessageFederation500Response(resp)
		if err != nil {
			return MessageFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type NewConversationResult struct {
	StatusCode int

	Response201 NewConversation201Response

	Response400 NewConversation400Response

	Response401 NewConversation401Response

	Response403 NewConversation403Response

	Response404 NewConversation404Response

	Response500 NewConversation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) NewConversation(ctx context.Context, params NewConversationRequest) (NewConversationResult, error) {
	if err := params.Validate(); err != nil {
		return NewConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return NewConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/conversations"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return NewConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return NewConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return NewConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := NewConversationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 201:
		result, err := NewNewConversation201Response(resp)
		if err != nil {
			return NewConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response201 = result
		return response, nil

	case 400:
		result, err := NewNewConversation400Response(resp)
		if err != nil {
			return NewConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewNewConversation401Response(resp)
		if err != nil {
			return NewConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewNewConversation403Response(resp)
		if err != nil {
			return NewConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewNewConversation404Response(resp)
		if err != nil {
			return NewConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewNewConversation500Response(resp)
		if err != nil {
			return NewConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type NewMessageResult struct {
	StatusCode int

	Response201 NewMessage201Response

	Response400 NewMessage400Response

	Response401 NewMessage401Response

	Response403 NewMessage403Response

	Response404 NewMessage404Response

	Response500 NewMessage500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) NewMessage(ctx context.Context, params NewMessageRequest) (NewMessageResult, error) {
	if err := params.Validate(); err != nil {
		return NewMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return NewMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/conversations/{conversationId}/messages"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return NewMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return NewMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return NewMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return NewMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := NewMessageResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 201:
		result, err := NewNewMessage201Response(resp)
		if err != nil {
			return NewMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response201 = result
		return response, nil

	case 400:
		result, err := NewNewMessage400Response(resp)
		if err != nil {
			return NewMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewNewMessage401Response(resp)
		if err != nil {
			return NewMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewNewMessage403Response(resp)
		if err != nil {
			return NewMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewNewMessage404Response(resp)
		if err != nil {
			return NewMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewNewMessage500Response(resp)
		if err != nil {
			return NewMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type PullUserEventsResult struct {
	StatusCode int

	Response200 PullUserEvents200Response

	Response400 PullUserEvents400Response

	Response401 PullUserEvents401Response

	Response500 PullUserEvents500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) PullUserEvents(ctx context.Context, params PullUserEventsRequest) (PullUserEventsResult, error) {
	if err := params.Validate(); err != nil {
		return PullUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/client/events"

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return PullUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return PullUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	q := req.URL.Query()

	queryCursor, err := paramToString(params.Cursor, "query parameter: Cursor", "*string", false)
	if err != nil {
		return PullUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid query parameter: cursor",
			Err:     err,
		}
	}
	q.Set("cursor", queryCursor)

	queryLimit, err := paramToString(params.Limit, "query parameter: Limit", "*float64", false)
	if err != nil {
		return PullUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid query parameter: limit",
			Err:     err,
		}
	}
	q.Set("limit", queryLimit)

	req.URL.RawQuery = q.Encode()

	resp, err := c.do(req)
	if err != nil {
		return PullUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := PullUserEventsResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewPullUserEvents200Response(resp)
		if err != nil {
			return PullUserEventsResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewPullUserEvents400Response(resp)
		if err != nil {
			return PullUserEventsResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewPullUserEvents401Response(resp)
		if err != nil {
			return PullUserEventsResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewPullUserEvents500Response(resp)
		if err != nil {
			return PullUserEventsResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type ReactToMessageResult struct {
	StatusCode int

	Response200 ReactToMessage200Response

	Response400 ReactToMessage400Response

	Response401 ReactToMessage401Response

	Response403 ReactToMessage403Response

	Response404 ReactToMessage404Response

	Response500 ReactToMessage500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) ReactToMessage(ctx context.Context, params ReactToMessageRequest) (ReactToMessageResult, error) {
	if err := params.Validate(); err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/react"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return ReactToMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := ReactToMessageResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewReactToMessage200Response(resp)
		if err != nil {
			return ReactToMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewReactToMessage400Response(resp)
		if err != nil {
			return ReactToMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewReactToMessage401Response(resp)
		if err != nil {
			return ReactToMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewReactToMessage403Response(resp)
		if err != nil {
			return ReactToMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewReactToMessage404Response(resp)
		if err != nil {
			return ReactToMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewReactToMessage500Response(resp)
		if err != nil {
			return ReactToMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type ReadMessageResult struct {
	StatusCode int

	Response200 ReadMessage200Response

	Response400 ReadMessage400Response

	Response401 ReadMessage401Response

	Response403 ReadMessage403Response

	Response404 ReadMessage404Response

	Response500 ReadMessage500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) ReadMessage(ctx context.Context, params ReadMessageRequest) (ReadMessageResult, error) {
	if err := params.Validate(); err != nil {
		return ReadMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/read"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return ReadMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return ReadMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return ReadMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return ReadMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return ReadMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := ReadMessageResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewReadMessage200Response(resp)
		if err != nil {
			return ReadMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewReadMessage400Response(resp)
		if err != nil {
			return ReadMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewReadMessage401Response(resp)
		if err != nil {
			return ReadMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewReadMessage403Response(resp)
		if err != nil {
			return ReadMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewReadMessage404Response(resp)
		if err != nil {
			return ReadMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewReadMessage500Response(resp)
		if err != nil {
			return ReadMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type RedactMessageResult struct {
	StatusCode int

	Response200 RedactMessage200Response

	Response400 RedactMessage400Response

	Response401 RedactMessage401Response

	Response403 RedactMessage403Response

	Response404 RedactMessage404Response

	Response500 RedactMessage500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) RedactMessage(ctx context.Context, params RedactMessageRequest) (RedactMessageResult, error) {
	if err := params.Validate(); err != nil {
		return RedactMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/redact"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return RedactMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return RedactMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return RedactMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return RedactMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return RedactMessageResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := RedactMessageResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewRedactMessage200Response(resp)
		if err != nil {
			return RedactMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewRedactMessage400Response(resp)
		if err != nil {
			return RedactMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewRedactMessage401Response(resp)
		if err != nil {
			return RedactMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewRedactMessage403Response(resp)
		if err != nil {
			return RedactMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewRedactMessage404Response(resp)
		if err != nil {
			return RedactMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewRedactMessage500Response(resp)
		if err != nil {
			return RedactMessageResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type RefreshSessionResult struct {
	StatusCode int

	Response200 RefreshSession200Response

	Response400 RefreshSession400Response

	Response401 RefreshSession401Response

	Response500 RefreshSession500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) RefreshSession(ctx context.Context, params RefreshSessionRequest) (RefreshSessionResult, error) {
	if err := params.Validate(); err != nil {
		return RefreshSessionResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return RefreshSessionResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/refresh-session"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return RefreshSessionResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return RefreshSessionResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := RefreshSessionResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewRefreshSession200Response(resp)
		if err != nil {
			return RefreshSessionResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewRefreshSession400Response(resp)
		if err != nil {
			return RefreshSessionResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewRefreshSession401Response(resp)
		if err != nil {
			return RefreshSessionResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewRefreshSession500Response(resp)
		if err != nil {
			return RefreshSessionResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type RequestResetPasswordResult struct {
	StatusCode int

	Response200 RequestResetPassword200Response

	Response400 RequestResetPassword400Response

	Response500 RequestResetPassword500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) RequestResetPassword(ctx context.Context, params RequestResetPasswordRequest) (RequestResetPasswordResult, error) {
	if err := params.Validate(); err != nil {
		return RequestResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return RequestResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/request-reset-password"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return RequestResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return RequestResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := RequestResetPasswordResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewRequestResetPassword200Response(resp)
		if err != nil {
			return RequestResetPasswordResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewRequestResetPassword400Response(resp)
		if err != nil {
			return RequestResetPasswordResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 500:
		result, err := NewRequestResetPassword500Response(resp)
		if err != nil {
			return RequestResetPasswordResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type ResetPasswordResult struct {
	StatusCode int

	Response200 ResetPassword200Response

	Response401 ResetPassword401Response

	Response500 ResetPassword500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) ResetPassword(ctx context.Context, params ResetPasswordRequest) (ResetPasswordResult, error) {
	if err := params.Validate(); err != nil {
		return ResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return ResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/reset-password"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return ResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return ResetPasswordResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := ResetPasswordResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewResetPassword200Response(resp)
		if err != nil {
			return ResetPasswordResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 401:
		result, err := NewResetPassword401Response(resp)
		if err != nil {
			return ResetPasswordResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewResetPassword500Response(resp)
		if err != nil {
			return ResetPasswordResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type SignUpResult struct {
	StatusCode int

	Response201 SignUp201Response

	Response400 SignUp400Response

	Response403 SignUp403Response

	Response409 SignUp409Response

	Response500 SignUp500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) SignUp(ctx context.Context, params SignUpRequest) (SignUpResult, error) {
	if err := params.Validate(); err != nil {
		return SignUpResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return SignUpResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/signup"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return SignUpResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return SignUpResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := SignUpResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 201:
		result, err := NewSignUp201Response(resp)
		if err != nil {
			return SignUpResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response201 = result
		return response, nil

	case 400:
		result, err := NewSignUp400Response(resp)
		if err != nil {
			return SignUpResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 403:
		result, err := NewSignUp403Response(resp)
		if err != nil {
			return SignUpResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 409:
		result, err := NewSignUp409Response(resp)
		if err != nil {
			return SignUpResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response409 = result
		return response, nil

	case 500:
		result, err := NewSignUp500Response(resp)
		if err != nil {
			return SignUpResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type UpdateConversationResult struct {
	StatusCode int

	Response200 UpdateConversation200Response

	Response400 UpdateConversation400Response

	Response401 UpdateConversation401Response

	Response403 UpdateConversation403Response

	Response404 UpdateConversation404Response

	Response500 UpdateConversation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) UpdateConversation(ctx context.Context, params UpdateConversationRequest) (UpdateConversationResult, error) {
	if err := params.Validate(); err != nil {
		return UpdateConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return UpdateConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/iimp/api/client/conversations/{conversationId}"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return UpdateConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	req, err := http.NewRequestWithContext(
		ctx,
		"PUT",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return UpdateConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return UpdateConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return UpdateConversationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := UpdateConversationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewUpdateConversation200Response(resp)
		if err != nil {
			return UpdateConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewUpdateConversation400Response(resp)
		if err != nil {
			return UpdateConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewUpdateConversation401Response(resp)
		if err != nil {
			return UpdateConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewUpdateConversation403Response(resp)
		if err != nil {
			return UpdateConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewUpdateConversation404Response(resp)
		if err != nil {
			return UpdateConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewUpdateConversation500Response(resp)
		if err != nil {
			return UpdateConversationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type UploadAttachmentResult struct {
	StatusCode int

	Response201 UploadAttachment201Response

	Response400 UploadAttachment400Response

	Response401 UploadAttachment401Response

	Response403 UploadAttachment403Response

	Response404 UploadAttachment404Response

	Response413 UploadAttachment413Response

	Response500 UploadAttachment500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) UploadAttachment(ctx context.Context, params UploadAttachmentRequest) (UploadAttachmentResult, error) {
	if err := params.Validate(); err != nil {
		return UploadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/iimp/api/client/attachments"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return UploadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	headerFilename, err := paramToString(params.Filename, "header parameter: Filename", "string", true)
	if err != nil {
		return UploadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid header parameter: X-IIMP-Attachment-Filename",
			Err:     err,
		}
	}
	req.Header.Set("X-IIMP-Attachment-Filename", headerFilename)

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return UploadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return UploadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := UploadAttachmentResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 201:
		result, err := NewUploadAttachment201Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response201 = result
		return response, nil

	case 400:
		result, err := NewUploadAttachment400Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewUploadAttachment401Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewUploadAttachment403Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewUploadAttachment404Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 413:
		result, err := NewUploadAttachment413Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response413 = result
		return response, nil

	case 500:
		result, err := NewUploadAttachment500Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response500 = result
		return response, nil

	default:
		response.UnknownResponse = &UnknownStatusResponse{
			StatusCode: resp.StatusCode,
			Response:   resp,
		}
		return response, nil
	}
}

type UnknownStatusResponse struct {
	StatusCode int
	Response   *http.Response
}

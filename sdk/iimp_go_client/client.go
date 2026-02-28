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
	path := "/api/client/keys"

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
	path := "/api/federation/conversations"

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
	path := "/api/client/conversations/{conversationId}/messages/{messageId}"

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

type EditMessageForwardFederationResult struct {
	StatusCode int

	Response200 EditMessageForwardFederation200Response

	Response400 EditMessageForwardFederation400Response

	Response401 EditMessageForwardFederation401Response

	Response403 EditMessageForwardFederation403Response

	Response404 EditMessageForwardFederation404Response

	Response500 EditMessageForwardFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) EditMessageForwardFederation(ctx context.Context, params EditMessageForwardFederationRequest) (EditMessageForwardFederationResult, error) {
	if err := params.Validate(); err != nil {
		return EditMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return EditMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/api/federation/conversations/{conversationId}/messages/{messageId}/edit/forward"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return EditMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return EditMessageForwardFederationResult{}, &IIMPError{
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
		return EditMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return EditMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return EditMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := EditMessageForwardFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewEditMessageForwardFederation200Response(resp)
		if err != nil {
			return EditMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewEditMessageForwardFederation400Response(resp)
		if err != nil {
			return EditMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewEditMessageForwardFederation401Response(resp)
		if err != nil {
			return EditMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewEditMessageForwardFederation403Response(resp)
		if err != nil {
			return EditMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewEditMessageForwardFederation404Response(resp)
		if err != nil {
			return EditMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewEditMessageForwardFederation500Response(resp)
		if err != nil {
			return EditMessageForwardFederationResult{}, &IIMPError{
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

type FetchAttachmentBytesResult struct {
	StatusCode int

	Response200 FetchAttachmentBytes200Response

	Response400 FetchAttachmentBytes400Response

	Response401 FetchAttachmentBytes401Response

	Response403 FetchAttachmentBytes403Response

	Response404 FetchAttachmentBytes404Response

	Response500 FetchAttachmentBytes500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) FetchAttachmentBytes(ctx context.Context, params FetchAttachmentBytesRequest) (FetchAttachmentBytesResult, error) {
	if err := params.Validate(); err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/api/client/conversations/{conversationId}/messages/{messageId}/attachments/{attachmentId}/bytes"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	pathParamAttachmentId, err := paramToString(params.AttachmentId, "path parameter: AttachmentId", "string", true)
	if err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: attachmentId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{attachmentId}", fmt.Sprintf("%v", pathParamAttachmentId))

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return FetchAttachmentBytesResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := FetchAttachmentBytesResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewFetchAttachmentBytes200Response(resp)
		if err != nil {
			return FetchAttachmentBytesResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewFetchAttachmentBytes400Response(resp)
		if err != nil {
			return FetchAttachmentBytesResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewFetchAttachmentBytes401Response(resp)
		if err != nil {
			return FetchAttachmentBytesResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewFetchAttachmentBytes403Response(resp)
		if err != nil {
			return FetchAttachmentBytesResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewFetchAttachmentBytes404Response(resp)
		if err != nil {
			return FetchAttachmentBytesResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewFetchAttachmentBytes500Response(resp)
		if err != nil {
			return FetchAttachmentBytesResult{}, &IIMPError{
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

type FetchAttachmentBytesFederationResult struct {
	StatusCode int

	Response200 FetchAttachmentBytesFederation200Response

	Response400 FetchAttachmentBytesFederation400Response

	Response401 FetchAttachmentBytesFederation401Response

	Response403 FetchAttachmentBytesFederation403Response

	Response404 FetchAttachmentBytesFederation404Response

	Response500 FetchAttachmentBytesFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) FetchAttachmentBytesFederation(ctx context.Context, params FetchAttachmentBytesFederationRequest) (FetchAttachmentBytesFederationResult, error) {
	if err := params.Validate(); err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/api/federation/conversations/{conversationId}/messages/{messageId}/attachments/{attachmentId}/bytes"

	pathParamAttachmentId, err := paramToString(params.AttachmentId, "path parameter: AttachmentId", "string", true)
	if err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: attachmentId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{attachmentId}", fmt.Sprintf("%v", pathParamAttachmentId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: messageId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{messageId}", fmt.Sprintf("%v", pathParamMessageId))

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return FetchAttachmentBytesFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := FetchAttachmentBytesFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewFetchAttachmentBytesFederation200Response(resp)
		if err != nil {
			return FetchAttachmentBytesFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewFetchAttachmentBytesFederation400Response(resp)
		if err != nil {
			return FetchAttachmentBytesFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewFetchAttachmentBytesFederation401Response(resp)
		if err != nil {
			return FetchAttachmentBytesFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewFetchAttachmentBytesFederation403Response(resp)
		if err != nil {
			return FetchAttachmentBytesFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewFetchAttachmentBytesFederation404Response(resp)
		if err != nil {
			return FetchAttachmentBytesFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewFetchAttachmentBytesFederation500Response(resp)
		if err != nil {
			return FetchAttachmentBytesFederationResult{}, &IIMPError{
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

	path := "/api/federation/users/{userId}"

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
	path := "/api/client/login"

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

	path := "/api/client/logout"

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
	path := "/api/federation/conversations/{conversationId}/messages"

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

type MessageForwardFederationResult struct {
	StatusCode int

	Response200 MessageForwardFederation200Response

	Response400 MessageForwardFederation400Response

	Response401 MessageForwardFederation401Response

	Response403 MessageForwardFederation403Response

	Response404 MessageForwardFederation404Response

	Response500 MessageForwardFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) MessageForwardFederation(ctx context.Context, params MessageForwardFederationRequest) (MessageForwardFederationResult, error) {
	if err := params.Validate(); err != nil {
		return MessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return MessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/api/federation/conversations/{conversationId}/messages/forward"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return MessageForwardFederationResult{}, &IIMPError{
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
		return MessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return MessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return MessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := MessageForwardFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewMessageForwardFederation200Response(resp)
		if err != nil {
			return MessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewMessageForwardFederation400Response(resp)
		if err != nil {
			return MessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewMessageForwardFederation401Response(resp)
		if err != nil {
			return MessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewMessageForwardFederation403Response(resp)
		if err != nil {
			return MessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewMessageForwardFederation404Response(resp)
		if err != nil {
			return MessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewMessageForwardFederation500Response(resp)
		if err != nil {
			return MessageForwardFederationResult{}, &IIMPError{
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

type NewAttachmentResult struct {
	StatusCode int

	Response201 NewAttachment201Response

	Response400 NewAttachment400Response

	Response401 NewAttachment401Response

	Response413 NewAttachment413Response

	Response500 NewAttachment500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) NewAttachment(ctx context.Context, params NewAttachmentRequest) (NewAttachmentResult, error) {
	if err := params.Validate(); err != nil {
		return NewAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return NewAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/api/client/attachments"

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.baseURL+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return NewAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return NewAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return NewAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := NewAttachmentResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 201:
		result, err := NewNewAttachment201Response(resp)
		if err != nil {
			return NewAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response201 = result
		return response, nil

	case 400:
		result, err := NewNewAttachment400Response(resp)
		if err != nil {
			return NewAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewNewAttachment401Response(resp)
		if err != nil {
			return NewAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 413:
		result, err := NewNewAttachment413Response(resp)
		if err != nil {
			return NewAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response413 = result
		return response, nil

	case 500:
		result, err := NewNewAttachment500Response(resp)
		if err != nil {
			return NewAttachmentResult{}, &IIMPError{
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
	path := "/api/client/conversations"

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
	path := "/api/client/conversations/{conversationId}/messages"

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
	path := "/api/client/conversations/{conversationId}/messages/{messageId}/react"

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

type ReactToMessageForwardFederationResult struct {
	StatusCode int

	Response200 ReactToMessageForwardFederation200Response

	Response400 ReactToMessageForwardFederation400Response

	Response401 ReactToMessageForwardFederation401Response

	Response403 ReactToMessageForwardFederation403Response

	Response404 ReactToMessageForwardFederation404Response

	Response500 ReactToMessageForwardFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) ReactToMessageForwardFederation(ctx context.Context, params ReactToMessageForwardFederationRequest) (ReactToMessageForwardFederationResult, error) {
	if err := params.Validate(); err != nil {
		return ReactToMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return ReactToMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/api/federation/conversations/{conversationId}/messages/{messageId}/react/forward"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return ReactToMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return ReactToMessageForwardFederationResult{}, &IIMPError{
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
		return ReactToMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return ReactToMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return ReactToMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := ReactToMessageForwardFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewReactToMessageForwardFederation200Response(resp)
		if err != nil {
			return ReactToMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewReactToMessageForwardFederation400Response(resp)
		if err != nil {
			return ReactToMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewReactToMessageForwardFederation401Response(resp)
		if err != nil {
			return ReactToMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewReactToMessageForwardFederation403Response(resp)
		if err != nil {
			return ReactToMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewReactToMessageForwardFederation404Response(resp)
		if err != nil {
			return ReactToMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewReactToMessageForwardFederation500Response(resp)
		if err != nil {
			return ReactToMessageForwardFederationResult{}, &IIMPError{
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

	path := "/api/client/conversations/{conversationId}/messages/{messageId}/read"

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

type ReadMessageForwardFederationResult struct {
	StatusCode int

	Response200 ReadMessageForwardFederation200Response

	Response400 ReadMessageForwardFederation400Response

	Response401 ReadMessageForwardFederation401Response

	Response403 ReadMessageForwardFederation403Response

	Response404 ReadMessageForwardFederation404Response

	Response500 ReadMessageForwardFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) ReadMessageForwardFederation(ctx context.Context, params ReadMessageForwardFederationRequest) (ReadMessageForwardFederationResult, error) {
	if err := params.Validate(); err != nil {
		return ReadMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return ReadMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/api/federation/conversations/{conversationId}/messages/{messageId}/read/forward"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return ReadMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return ReadMessageForwardFederationResult{}, &IIMPError{
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
		return ReadMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return ReadMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return ReadMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := ReadMessageForwardFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewReadMessageForwardFederation200Response(resp)
		if err != nil {
			return ReadMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewReadMessageForwardFederation400Response(resp)
		if err != nil {
			return ReadMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewReadMessageForwardFederation401Response(resp)
		if err != nil {
			return ReadMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewReadMessageForwardFederation403Response(resp)
		if err != nil {
			return ReadMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewReadMessageForwardFederation404Response(resp)
		if err != nil {
			return ReadMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewReadMessageForwardFederation500Response(resp)
		if err != nil {
			return ReadMessageForwardFederationResult{}, &IIMPError{
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

	path := "/api/client/conversations/{conversationId}/messages/{messageId}/redact"

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

type RedactMessageForwardFederationResult struct {
	StatusCode int

	Response200 RedactMessageForwardFederation200Response

	Response400 RedactMessageForwardFederation400Response

	Response401 RedactMessageForwardFederation401Response

	Response403 RedactMessageForwardFederation403Response

	Response404 RedactMessageForwardFederation404Response

	Response500 RedactMessageForwardFederation500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) RedactMessageForwardFederation(ctx context.Context, params RedactMessageForwardFederationRequest) (RedactMessageForwardFederationResult, error) {
	if err := params.Validate(); err != nil {
		return RedactMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	body, err := json.Marshal(params.Body)
	if err != nil {
		return RedactMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to serialize request body",
			Err:     err,
		}
	}
	path := "/api/federation/conversations/{conversationId}/messages/{messageId}/redact/forward"

	pathParamConversationId, err := paramToString(params.ConversationId, "path parameter: ConversationId", "string", true)
	if err != nil {
		return RedactMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: conversationId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{conversationId}", fmt.Sprintf("%v", pathParamConversationId))

	pathParamMessageId, err := paramToString(params.MessageId, "path parameter: MessageId", "string", true)
	if err != nil {
		return RedactMessageForwardFederationResult{}, &IIMPError{
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
		return RedactMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	req.Header.Set("Content-Type", "application/json")

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return RedactMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	resp, err := c.do(req)
	if err != nil {
		return RedactMessageForwardFederationResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := RedactMessageForwardFederationResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewRedactMessageForwardFederation200Response(resp)
		if err != nil {
			return RedactMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 400:
		result, err := NewRedactMessageForwardFederation400Response(resp)
		if err != nil {
			return RedactMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response400 = result
		return response, nil

	case 401:
		result, err := NewRedactMessageForwardFederation401Response(resp)
		if err != nil {
			return RedactMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 403:
		result, err := NewRedactMessageForwardFederation403Response(resp)
		if err != nil {
			return RedactMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response403 = result
		return response, nil

	case 404:
		result, err := NewRedactMessageForwardFederation404Response(resp)
		if err != nil {
			return RedactMessageForwardFederationResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response404 = result
		return response, nil

	case 500:
		result, err := NewRedactMessageForwardFederation500Response(resp)
		if err != nil {
			return RedactMessageForwardFederationResult{}, &IIMPError{
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
	path := "/api/client/refresh-session"

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
	path := "/api/client/request-reset-password"

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
	path := "/api/client/reset-password"

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
	path := "/api/client/signup"

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

type SyncUserEventsResult struct {
	StatusCode int

	Response200 SyncUserEvents200Response

	Response401 SyncUserEvents401Response

	Response500 SyncUserEvents500Response

	UnknownResponse *UnknownStatusResponse
}

func (c *IIMP) SyncUserEvents(ctx context.Context, params SyncUserEventsRequest) (SyncUserEventsResult, error) {
	if err := params.Validate(); err != nil {
		return SyncUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid request parameters",
			Err:     err,
		}
	}

	path := "/api/client/events/sync"

	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.baseURL+path,
		nil,
	)
	if err != nil {
		return SyncUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "failed to create HTTP request",
			Err:     err,
		}
	}

	authAuthorization, err := paramToString(params.Auth.Authorization, "auth parameter: Authorization", "*string", true)
	if err != nil {
		return SyncUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid auth parameter: Authorization",
			Err:     err,
		}
	}
	req.Header.Set("Authorization", authAuthorization)

	q := req.URL.Query()

	queryCursor, err := paramToString(params.Cursor, "query parameter: Cursor", "*float64", false)
	if err != nil {
		return SyncUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid query parameter: cursor",
			Err:     err,
		}
	}
	q.Set("cursor", queryCursor)

	queryLimit, err := paramToString(params.Limit, "query parameter: Limit", "*float64", false)
	if err != nil {
		return SyncUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid query parameter: limit",
			Err:     err,
		}
	}
	q.Set("limit", queryLimit)

	req.URL.RawQuery = q.Encode()

	resp, err := c.do(req)
	if err != nil {
		return SyncUserEventsResult{}, &IIMPError{
			Reason:  IIMPErrorReasonNetworkError,
			Message: "network error during HTTP request",
			Err:     err,
		}
	}
	// resp.Body will be closed in response handlers
	response := SyncUserEventsResult{
		StatusCode: resp.StatusCode,
	}
	switch resp.StatusCode {

	case 200:
		result, err := NewSyncUserEvents200Response(resp)
		if err != nil {
			return SyncUserEventsResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response200 = result
		return response, nil

	case 401:
		result, err := NewSyncUserEvents401Response(resp)
		if err != nil {
			return SyncUserEventsResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response401 = result
		return response, nil

	case 500:
		result, err := NewSyncUserEvents500Response(resp)
		if err != nil {
			return SyncUserEventsResult{}, &IIMPError{
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
	path := "/api/client/conversations/{conversationId}"

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

	Response204 UploadAttachment204Response

	Response400 UploadAttachment400Response

	Response401 UploadAttachment401Response

	Response403 UploadAttachment403Response

	Response404 UploadAttachment404Response

	Response409 UploadAttachment409Response

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

	path := "/api/client/attachments/{attachmentId}/bytes"

	pathParamAttachmentId, err := paramToString(params.AttachmentId, "path parameter: AttachmentId", "string", true)
	if err != nil {
		return UploadAttachmentResult{}, &IIMPError{
			Reason:  IIMPErrorReasonInvalidRequest,
			Message: "invalid path parameter: attachmentId",
			Err:     err,
		}
	}
	path = strings.ReplaceAll(path, "{attachmentId}", fmt.Sprintf("%v", pathParamAttachmentId))

	req, err := http.NewRequestWithContext(
		ctx,
		"PUT",
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

	case 204:
		result, err := NewUploadAttachment204Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response204 = result
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

	case 409:
		result, err := NewUploadAttachment409Response(resp)
		if err != nil {
			return UploadAttachmentResult{}, &IIMPError{
				Reason:  IIMPErrorReasonDecodeError,
				Message: "failed to decode response",
				Err:     err,
			}
		}
		response.Response409 = result
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

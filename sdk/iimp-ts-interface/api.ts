

import { IIMPError } from "./models";
import * as Models from "./models";

export class IIMP {
  private baseURL: string;
  private headers: Record<string, string>;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
    this.headers = {
      'Accept': 'application/json',
      'User-Agent': 'IIMP-TypeScriptSDK/1.0.0'
    };
  }

  private addHeaders(request: RequestInit): RequestInit {
    request.headers = { ...this.headers, ...request.headers };
    return request;
  }

  
  
  // Throws IIMPError, or a network error
  async AddPublicKey(params: Models.AddPublicKeyRequest): Promise<AddPublicKeyResult> {
    var result = {} as AddPublicKeyResult;
    Models.ValidateAddPublicKeyRequest(params);

    var path = "/api/client/keys";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 201:
        result.Response201 = await Models.NewAddPublicKey201Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewAddPublicKey400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewAddPublicKey401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewAddPublicKey500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async ConversationFederation(params: Models.ConversationFederationRequest): Promise<ConversationFederationResult> {
    var result = {} as ConversationFederationResult;
    Models.ValidateConversationFederationRequest(params);

    var path = "/api/federation/conversations";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewConversationFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewConversationFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewConversationFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewConversationFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewConversationFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewConversationFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async DiscoverServer(params: Models.DiscoverServerRequest): Promise<DiscoverServerResult> {
    var result = {} as DiscoverServerResult;
    Models.ValidateDiscoverServerRequest(params);

    var path = "/.well-known/iimp";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewDiscoverServer200Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewDiscoverServer500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async EditMessage(params: Models.EditMessageRequest): Promise<EditMessageResult> {
    var result = {} as EditMessageResult;
    Models.ValidateEditMessageRequest(params);

    var path = "/api/client/conversations/{conversationId}/messages/{messageId}";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "PUT",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewEditMessage200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewEditMessage400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewEditMessage401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewEditMessage403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewEditMessage404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewEditMessage500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async EditMessageForwardFederation(params: Models.EditMessageForwardFederationRequest): Promise<EditMessageForwardFederationResult> {
    var result = {} as EditMessageForwardFederationResult;
    Models.ValidateEditMessageForwardFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages/{messageId}/edit/forward";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "PUT",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewEditMessageForwardFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewEditMessageForwardFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewEditMessageForwardFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewEditMessageForwardFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewEditMessageForwardFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewEditMessageForwardFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async FetchAttachmentBytes(params: Models.FetchAttachmentBytesRequest): Promise<FetchAttachmentBytesResult> {
    var result = {} as FetchAttachmentBytesResult;
    Models.ValidateFetchAttachmentBytesRequest(params);

    var path = "/api/client/conversations/{conversationId}/messages/{messageId}/attachments/{attachmentId}/bytes";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    var pathParamAttachmentId = paramToString(params.AttachmentId, "path parameter: AttachmentId", "string", true);
    path = path.replace("{attachmentId}", encodeURIComponent(pathParamAttachmentId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewFetchAttachmentBytes200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewFetchAttachmentBytes400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewFetchAttachmentBytes401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewFetchAttachmentBytes403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewFetchAttachmentBytes404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewFetchAttachmentBytes500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async FetchAttachmentBytesFederation(params: Models.FetchAttachmentBytesFederationRequest): Promise<FetchAttachmentBytesFederationResult> {
    var result = {} as FetchAttachmentBytesFederationResult;
    Models.ValidateFetchAttachmentBytesFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages/{messageId}/attachments/{attachmentId}/bytes";
    
    var pathParamAttachmentId = paramToString(params.AttachmentId, "path parameter: AttachmentId", "string", true);
    path = path.replace("{attachmentId}", encodeURIComponent(pathParamAttachmentId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewFetchAttachmentBytesFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewFetchAttachmentBytesFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewFetchAttachmentBytesFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewFetchAttachmentBytesFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewFetchAttachmentBytesFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewFetchAttachmentBytesFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async GetJWKSStore(params: Models.GetJWKSStoreRequest): Promise<GetJWKSStoreResult> {
    var result = {} as GetJWKSStoreResult;
    Models.ValidateGetJWKSStoreRequest(params);

    var path = "/.well-known/iimp/jwks";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewGetJWKSStore200Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewGetJWKSStore500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async GetUserInfoFederation(params: Models.GetUserInfoFederationRequest): Promise<GetUserInfoFederationResult> {
    var result = {} as GetUserInfoFederationResult;
    Models.ValidateGetUserInfoFederationRequest(params);

    var path = "/api/federation/users/{userId}";
    
    var pathParamUserId = paramToString(params.UserId, "path parameter: UserId", "string", true);
    path = path.replace("{userId}", encodeURIComponent(pathParamUserId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewGetUserInfoFederation200Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewGetUserInfoFederation401Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewGetUserInfoFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewGetUserInfoFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async GetUserPublicKey(params: Models.GetUserPublicKeyRequest): Promise<GetUserPublicKeyResult> {
    var result = {} as GetUserPublicKeyResult;
    Models.ValidateGetUserPublicKeyRequest(params);

    var path = "/.well-known/iimp/keys/users/{userId}";
    
    var pathParamUserId = paramToString(params.UserId, "path parameter: UserId", "string", true);
    path = path.replace("{userId}", encodeURIComponent(pathParamUserId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewGetUserPublicKey200Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewGetUserPublicKey404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewGetUserPublicKey500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async GetUserPublicKeyById(params: Models.GetUserPublicKeyByIdRequest): Promise<GetUserPublicKeyByIdResult> {
    var result = {} as GetUserPublicKeyByIdResult;
    Models.ValidateGetUserPublicKeyByIdRequest(params);

    var path = "/.well-known/iimp/keys/users/{userId}/{keyId}";
    
    var pathParamUserId = paramToString(params.UserId, "path parameter: UserId", "string", true);
    path = path.replace("{userId}", encodeURIComponent(pathParamUserId));
    
    var pathParamKeyId = paramToString(params.KeyId, "path parameter: KeyId", "string", true);
    path = path.replace("{keyId}", encodeURIComponent(pathParamKeyId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewGetUserPublicKeyById200Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewGetUserPublicKeyById404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewGetUserPublicKeyById500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async Login(params: Models.LoginRequest): Promise<LoginResult> {
    var result = {} as LoginResult;
    Models.ValidateLoginRequest(params);

    var path = "/api/client/login";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewLogin200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewLogin400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewLogin401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewLogin500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async Logout(params: Models.LogoutRequest): Promise<LogoutResult> {
    var result = {} as LogoutResult;
    Models.ValidateLogoutRequest(params);

    var path = "/api/client/logout";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 204:
        result.Response204 = await Models.NewLogout204Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewLogout401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewLogout500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async MessageFederation(params: Models.MessageFederationRequest): Promise<MessageFederationResult> {
    var result = {} as MessageFederationResult;
    Models.ValidateMessageFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewMessageFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewMessageFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewMessageFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewMessageFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewMessageFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewMessageFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async MessageForwardFederation(params: Models.MessageForwardFederationRequest): Promise<MessageForwardFederationResult> {
    var result = {} as MessageForwardFederationResult;
    Models.ValidateMessageForwardFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages/forward";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewMessageForwardFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewMessageForwardFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewMessageForwardFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewMessageForwardFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewMessageForwardFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewMessageForwardFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async NewAttachment(params: Models.NewAttachmentRequest): Promise<NewAttachmentResult> {
    var result = {} as NewAttachmentResult;
    Models.ValidateNewAttachmentRequest(params);

    var path = "/api/client/attachments";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 201:
        result.Response201 = await Models.NewNewAttachment201Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewNewAttachment400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewNewAttachment401Response(response);
        break;
    
      case 413:
        result.Response413 = await Models.NewNewAttachment413Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewNewAttachment500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async NewConversation(params: Models.NewConversationRequest): Promise<NewConversationResult> {
    var result = {} as NewConversationResult;
    Models.ValidateNewConversationRequest(params);

    var path = "/api/client/conversations";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 201:
        result.Response201 = await Models.NewNewConversation201Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewNewConversation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewNewConversation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewNewConversation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewNewConversation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewNewConversation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async NewMessage(params: Models.NewMessageRequest): Promise<NewMessageResult> {
    var result = {} as NewMessageResult;
    Models.ValidateNewMessageRequest(params);

    var path = "/api/client/conversations/{conversationId}/messages";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 201:
        result.Response201 = await Models.NewNewMessage201Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewNewMessage400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewNewMessage401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewNewMessage403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewNewMessage404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewNewMessage500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async ReactToMessage(params: Models.ReactToMessageRequest): Promise<ReactToMessageResult> {
    var result = {} as ReactToMessageResult;
    Models.ValidateReactToMessageRequest(params);

    var path = "/api/client/conversations/{conversationId}/messages/{messageId}/react";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewReactToMessage200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewReactToMessage400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewReactToMessage401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewReactToMessage403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewReactToMessage404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewReactToMessage500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async ReactToMessageForwardFederation(params: Models.ReactToMessageForwardFederationRequest): Promise<ReactToMessageForwardFederationResult> {
    var result = {} as ReactToMessageForwardFederationResult;
    Models.ValidateReactToMessageForwardFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages/{messageId}/react/forward";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewReactToMessageForwardFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewReactToMessageForwardFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewReactToMessageForwardFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewReactToMessageForwardFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewReactToMessageForwardFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewReactToMessageForwardFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async ReadMessage(params: Models.ReadMessageRequest): Promise<ReadMessageResult> {
    var result = {} as ReadMessageResult;
    Models.ValidateReadMessageRequest(params);

    var path = "/api/client/conversations/{conversationId}/messages/{messageId}/read";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewReadMessage200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewReadMessage400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewReadMessage401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewReadMessage403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewReadMessage404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewReadMessage500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async ReadMessageForwardFederation(params: Models.ReadMessageForwardFederationRequest): Promise<ReadMessageForwardFederationResult> {
    var result = {} as ReadMessageForwardFederationResult;
    Models.ValidateReadMessageForwardFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages/{messageId}/read/forward";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewReadMessageForwardFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewReadMessageForwardFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewReadMessageForwardFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewReadMessageForwardFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewReadMessageForwardFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewReadMessageForwardFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async RedactMessage(params: Models.RedactMessageRequest): Promise<RedactMessageResult> {
    var result = {} as RedactMessageResult;
    Models.ValidateRedactMessageRequest(params);

    var path = "/api/client/conversations/{conversationId}/messages/{messageId}/redact";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewRedactMessage200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewRedactMessage400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewRedactMessage401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewRedactMessage403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewRedactMessage404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewRedactMessage500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async RedactMessageForwardFederation(params: Models.RedactMessageForwardFederationRequest): Promise<RedactMessageForwardFederationResult> {
    var result = {} as RedactMessageForwardFederationResult;
    Models.ValidateRedactMessageForwardFederationRequest(params);

    var path = "/api/federation/conversations/{conversationId}/messages/{messageId}/redact/forward";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewRedactMessageForwardFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewRedactMessageForwardFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewRedactMessageForwardFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewRedactMessageForwardFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewRedactMessageForwardFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewRedactMessageForwardFederation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async RefreshSession(params: Models.RefreshSessionRequest): Promise<RefreshSessionResult> {
    var result = {} as RefreshSessionResult;
    Models.ValidateRefreshSessionRequest(params);

    var path = "/api/client/refresh-session";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewRefreshSession200Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewRefreshSession401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewRefreshSession500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async RequestResetPassword(params: Models.RequestResetPasswordRequest): Promise<RequestResetPasswordResult> {
    var result = {} as RequestResetPasswordResult;
    Models.ValidateRequestResetPasswordRequest(params);

    var path = "/api/client/request-reset-password";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewRequestResetPassword200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewRequestResetPassword400Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewRequestResetPassword500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async ResetPassword(params: Models.ResetPasswordRequest): Promise<ResetPasswordResult> {
    var result = {} as ResetPasswordResult;
    Models.ValidateResetPasswordRequest(params);

    var path = "/api/client/reset-password";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewResetPassword200Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewResetPassword401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewResetPassword500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async SignUp(params: Models.SignUpRequest): Promise<SignUpResult> {
    var result = {} as SignUpResult;
    Models.ValidateSignUpRequest(params);

    var path = "/api/client/signup";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 201:
        result.Response201 = await Models.NewSignUp201Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewSignUp400Response(response);
        break;
    
      case 409:
        result.Response409 = await Models.NewSignUp409Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewSignUp500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async SyncUserEvents(params: Models.SyncUserEventsRequest): Promise<SyncUserEventsResult> {
    var result = {} as SyncUserEventsResult;
    Models.ValidateSyncUserEventsRequest(params);

    var path = "/api/client/events/sync";
    
    const url = new URL(this.baseURL + path);
    
    var queryParamCursor = paramToString(params.Cursor, "query parameter: Cursor", "number", false);
    if (queryParamCursor !== "") {
      url.searchParams.append("cursor", queryParamCursor);
    }
    
    var queryParamLimit = paramToString(params.Limit, "query parameter: Limit", "number", false);
    if (queryParamLimit !== "") {
      url.searchParams.append("limit", queryParamLimit);
    }
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewSyncUserEvents200Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewSyncUserEvents401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewSyncUserEvents500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async UpdateConversation(params: Models.UpdateConversationRequest): Promise<UpdateConversationResult> {
    var result = {} as UpdateConversationResult;
    Models.ValidateUpdateConversationRequest(params);

    var path = "/api/client/conversations/{conversationId}";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "PUT",
    }
    
    
    requestInit.body = JSON.stringify(params.Body);
    requestInit.headers = { ...requestInit.headers, 'Content-Type': 'application/json' };
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewUpdateConversation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewUpdateConversation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewUpdateConversation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewUpdateConversation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewUpdateConversation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewUpdateConversation500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
  
  // Throws IIMPError, or a network error
  async UploadAttachment(params: Models.UploadAttachmentRequest): Promise<UploadAttachmentResult> {
    var result = {} as UploadAttachmentResult;
    Models.ValidateUploadAttachmentRequest(params);

    var path = "/api/client/attachments/{attachmentId}/bytes";
    
    var pathParamAttachmentId = paramToString(params.AttachmentId, "path parameter: AttachmentId", "string", true);
    path = path.replace("{attachmentId}", encodeURIComponent(pathParamAttachmentId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "PUT",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 204:
        result.Response204 = await Models.NewUploadAttachment204Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewUploadAttachment400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewUploadAttachment401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewUploadAttachment403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewUploadAttachment404Response(response);
        break;
    
      case 409:
        result.Response409 = await Models.NewUploadAttachment409Response(response);
        break;
    
      case 413:
        result.Response413 = await Models.NewUploadAttachment413Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewUploadAttachment500Response(response);
        break;
    
      default:
        result.UnknownResponse = {
          StatusCode: response.status,
          Resp: response,
        };
    }
    return result;
  }
  
}


type AddPublicKeyResult = {
  StatusCode: number;
  
  Response201: Models.AddPublicKey201Response;
  
  Response400: Models.AddPublicKey400Response;
  
  Response401: Models.AddPublicKey401Response;
  
  Response500: Models.AddPublicKey500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type ConversationFederationResult = {
  StatusCode: number;
  
  Response200: Models.ConversationFederation200Response;
  
  Response400: Models.ConversationFederation400Response;
  
  Response401: Models.ConversationFederation401Response;
  
  Response403: Models.ConversationFederation403Response;
  
  Response404: Models.ConversationFederation404Response;
  
  Response500: Models.ConversationFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type DiscoverServerResult = {
  StatusCode: number;
  
  Response200: Models.DiscoverServer200Response;
  
  Response500: Models.DiscoverServer500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type EditMessageResult = {
  StatusCode: number;
  
  Response200: Models.EditMessage200Response;
  
  Response400: Models.EditMessage400Response;
  
  Response401: Models.EditMessage401Response;
  
  Response403: Models.EditMessage403Response;
  
  Response404: Models.EditMessage404Response;
  
  Response500: Models.EditMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type EditMessageForwardFederationResult = {
  StatusCode: number;
  
  Response200: Models.EditMessageForwardFederation200Response;
  
  Response400: Models.EditMessageForwardFederation400Response;
  
  Response401: Models.EditMessageForwardFederation401Response;
  
  Response403: Models.EditMessageForwardFederation403Response;
  
  Response404: Models.EditMessageForwardFederation404Response;
  
  Response500: Models.EditMessageForwardFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type FetchAttachmentBytesResult = {
  StatusCode: number;
  
  Response200: Models.FetchAttachmentBytes200Response;
  
  Response400: Models.FetchAttachmentBytes400Response;
  
  Response401: Models.FetchAttachmentBytes401Response;
  
  Response403: Models.FetchAttachmentBytes403Response;
  
  Response404: Models.FetchAttachmentBytes404Response;
  
  Response500: Models.FetchAttachmentBytes500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type FetchAttachmentBytesFederationResult = {
  StatusCode: number;
  
  Response200: Models.FetchAttachmentBytesFederation200Response;
  
  Response400: Models.FetchAttachmentBytesFederation400Response;
  
  Response401: Models.FetchAttachmentBytesFederation401Response;
  
  Response403: Models.FetchAttachmentBytesFederation403Response;
  
  Response404: Models.FetchAttachmentBytesFederation404Response;
  
  Response500: Models.FetchAttachmentBytesFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type GetJWKSStoreResult = {
  StatusCode: number;
  
  Response200: Models.GetJWKSStore200Response;
  
  Response500: Models.GetJWKSStore500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type GetUserInfoFederationResult = {
  StatusCode: number;
  
  Response200: Models.GetUserInfoFederation200Response;
  
  Response401: Models.GetUserInfoFederation401Response;
  
  Response404: Models.GetUserInfoFederation404Response;
  
  Response500: Models.GetUserInfoFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type GetUserPublicKeyResult = {
  StatusCode: number;
  
  Response200: Models.GetUserPublicKey200Response;
  
  Response404: Models.GetUserPublicKey404Response;
  
  Response500: Models.GetUserPublicKey500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type GetUserPublicKeyByIdResult = {
  StatusCode: number;
  
  Response200: Models.GetUserPublicKeyById200Response;
  
  Response404: Models.GetUserPublicKeyById404Response;
  
  Response500: Models.GetUserPublicKeyById500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type LoginResult = {
  StatusCode: number;
  
  Response200: Models.Login200Response;
  
  Response400: Models.Login400Response;
  
  Response401: Models.Login401Response;
  
  Response500: Models.Login500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type LogoutResult = {
  StatusCode: number;
  
  Response204: Models.Logout204Response;
  
  Response401: Models.Logout401Response;
  
  Response500: Models.Logout500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type MessageFederationResult = {
  StatusCode: number;
  
  Response200: Models.MessageFederation200Response;
  
  Response400: Models.MessageFederation400Response;
  
  Response401: Models.MessageFederation401Response;
  
  Response403: Models.MessageFederation403Response;
  
  Response404: Models.MessageFederation404Response;
  
  Response500: Models.MessageFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type MessageForwardFederationResult = {
  StatusCode: number;
  
  Response200: Models.MessageForwardFederation200Response;
  
  Response400: Models.MessageForwardFederation400Response;
  
  Response401: Models.MessageForwardFederation401Response;
  
  Response403: Models.MessageForwardFederation403Response;
  
  Response404: Models.MessageForwardFederation404Response;
  
  Response500: Models.MessageForwardFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type NewAttachmentResult = {
  StatusCode: number;
  
  Response201: Models.NewAttachment201Response;
  
  Response400: Models.NewAttachment400Response;
  
  Response401: Models.NewAttachment401Response;
  
  Response413: Models.NewAttachment413Response;
  
  Response500: Models.NewAttachment500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type NewConversationResult = {
  StatusCode: number;
  
  Response201: Models.NewConversation201Response;
  
  Response400: Models.NewConversation400Response;
  
  Response401: Models.NewConversation401Response;
  
  Response403: Models.NewConversation403Response;
  
  Response404: Models.NewConversation404Response;
  
  Response500: Models.NewConversation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type NewMessageResult = {
  StatusCode: number;
  
  Response201: Models.NewMessage201Response;
  
  Response400: Models.NewMessage400Response;
  
  Response401: Models.NewMessage401Response;
  
  Response403: Models.NewMessage403Response;
  
  Response404: Models.NewMessage404Response;
  
  Response500: Models.NewMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type ReactToMessageResult = {
  StatusCode: number;
  
  Response200: Models.ReactToMessage200Response;
  
  Response400: Models.ReactToMessage400Response;
  
  Response401: Models.ReactToMessage401Response;
  
  Response403: Models.ReactToMessage403Response;
  
  Response404: Models.ReactToMessage404Response;
  
  Response500: Models.ReactToMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type ReactToMessageForwardFederationResult = {
  StatusCode: number;
  
  Response200: Models.ReactToMessageForwardFederation200Response;
  
  Response400: Models.ReactToMessageForwardFederation400Response;
  
  Response401: Models.ReactToMessageForwardFederation401Response;
  
  Response403: Models.ReactToMessageForwardFederation403Response;
  
  Response404: Models.ReactToMessageForwardFederation404Response;
  
  Response500: Models.ReactToMessageForwardFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type ReadMessageResult = {
  StatusCode: number;
  
  Response200: Models.ReadMessage200Response;
  
  Response400: Models.ReadMessage400Response;
  
  Response401: Models.ReadMessage401Response;
  
  Response403: Models.ReadMessage403Response;
  
  Response404: Models.ReadMessage404Response;
  
  Response500: Models.ReadMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type ReadMessageForwardFederationResult = {
  StatusCode: number;
  
  Response200: Models.ReadMessageForwardFederation200Response;
  
  Response400: Models.ReadMessageForwardFederation400Response;
  
  Response401: Models.ReadMessageForwardFederation401Response;
  
  Response403: Models.ReadMessageForwardFederation403Response;
  
  Response404: Models.ReadMessageForwardFederation404Response;
  
  Response500: Models.ReadMessageForwardFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type RedactMessageResult = {
  StatusCode: number;
  
  Response200: Models.RedactMessage200Response;
  
  Response400: Models.RedactMessage400Response;
  
  Response401: Models.RedactMessage401Response;
  
  Response403: Models.RedactMessage403Response;
  
  Response404: Models.RedactMessage404Response;
  
  Response500: Models.RedactMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type RedactMessageForwardFederationResult = {
  StatusCode: number;
  
  Response200: Models.RedactMessageForwardFederation200Response;
  
  Response400: Models.RedactMessageForwardFederation400Response;
  
  Response401: Models.RedactMessageForwardFederation401Response;
  
  Response403: Models.RedactMessageForwardFederation403Response;
  
  Response404: Models.RedactMessageForwardFederation404Response;
  
  Response500: Models.RedactMessageForwardFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type RefreshSessionResult = {
  StatusCode: number;
  
  Response200: Models.RefreshSession200Response;
  
  Response401: Models.RefreshSession401Response;
  
  Response500: Models.RefreshSession500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type RequestResetPasswordResult = {
  StatusCode: number;
  
  Response200: Models.RequestResetPassword200Response;
  
  Response400: Models.RequestResetPassword400Response;
  
  Response500: Models.RequestResetPassword500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type ResetPasswordResult = {
  StatusCode: number;
  
  Response200: Models.ResetPassword200Response;
  
  Response401: Models.ResetPassword401Response;
  
  Response500: Models.ResetPassword500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type SignUpResult = {
  StatusCode: number;
  
  Response201: Models.SignUp201Response;
  
  Response400: Models.SignUp400Response;
  
  Response409: Models.SignUp409Response;
  
  Response500: Models.SignUp500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type SyncUserEventsResult = {
  StatusCode: number;
  
  Response200: Models.SyncUserEvents200Response;
  
  Response401: Models.SyncUserEvents401Response;
  
  Response500: Models.SyncUserEvents500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type UpdateConversationResult = {
  StatusCode: number;
  
  Response200: Models.UpdateConversation200Response;
  
  Response400: Models.UpdateConversation400Response;
  
  Response401: Models.UpdateConversation401Response;
  
  Response403: Models.UpdateConversation403Response;
  
  Response404: Models.UpdateConversation404Response;
  
  Response500: Models.UpdateConversation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

type UploadAttachmentResult = {
  StatusCode: number;
  
  Response204: Models.UploadAttachment204Response;
  
  Response400: Models.UploadAttachment400Response;
  
  Response401: Models.UploadAttachment401Response;
  
  Response403: Models.UploadAttachment403Response;
  
  Response404: Models.UploadAttachment404Response;
  
  Response409: Models.UploadAttachment409Response;
  
  Response413: Models.UploadAttachment413Response;
  
  Response500: Models.UploadAttachment500Response;
  
  UnknownResponse: UnknownStatusResponse;
}


type UnknownStatusResponse = {
  StatusCode: number;
  Resp: Response;
}

function paramToString(param: any, paramDescription: string, expectedType: string, required: boolean): string {
  if (param === undefined || param === null) {
    if (required) {
      throw new IIMPError(Models.IIMPErrorReasonInvalidRequest, `${paramDescription} is required but was not provided`);
    } else {
      return "";
    }
  }

  if (typeof param === "string") {
    return param;
  } else if (typeof param === "number" || typeof param === "boolean") {
    return param.toString();
  } else {
    throw new IIMPError(Models.IIMPErrorReasonInvalidRequest, `${paramDescription} should be of type ${expectedType} but got ${typeof param}`);
  }
}


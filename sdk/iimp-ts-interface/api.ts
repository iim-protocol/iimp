

import { IIMPError } from "./models";
import * as Models from "./models";

export const IIMPVersion = "0.0.1";

export class IIMP {
  private baseURL: string;
  private headers: Record<string, string>;

  constructor(baseURL: string) {
    this.baseURL = baseURL;
    this.headers = {
      'Accept': 'application/json',
      'User-Agent': 'IIMP-TypeScriptSDK/0.0.1'
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

    var path = "/iimp/api/client/keys";
    
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

    var path = "/iimp/api/federation/conversations";
    
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
    
      case 404:
        result.Response404 = await Models.NewDiscoverServer404Response(response);
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
  async DownloadAttachment(params: Models.DownloadAttachmentRequest): Promise<DownloadAttachmentResult> {
    var result = {} as DownloadAttachmentResult;
    Models.ValidateDownloadAttachmentRequest(params);

    var path = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/attachments/{fileId}/bytes";
    
    var pathParamConversationId = paramToString(params.ConversationId, "path parameter: ConversationId", "string", true);
    path = path.replace("{conversationId}", encodeURIComponent(pathParamConversationId));
    
    var pathParamMessageId = paramToString(params.MessageId, "path parameter: MessageId", "string", true);
    path = path.replace("{messageId}", encodeURIComponent(pathParamMessageId));
    
    var pathParamFileId = paramToString(params.FileId, "path parameter: FileId", "string", true);
    path = path.replace("{fileId}", encodeURIComponent(pathParamFileId));
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "GET",
    }
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 200:
        result.Response200 = await Models.NewDownloadAttachment200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewDownloadAttachment400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewDownloadAttachment401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewDownloadAttachment403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewDownloadAttachment404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewDownloadAttachment500Response(response);
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
  async DownloadAttachmentBytesFederation(params: Models.DownloadAttachmentBytesFederationRequest): Promise<DownloadAttachmentBytesFederationResult> {
    var result = {} as DownloadAttachmentBytesFederationResult;
    Models.ValidateDownloadAttachmentBytesFederationRequest(params);

    var path = "/iimp/api/federation/conversations/{conversationId}/messages/{messageId}/attachments/{fileId}/bytes";
    
    var pathParamFileId = paramToString(params.FileId, "path parameter: FileId", "string", true);
    path = path.replace("{fileId}", encodeURIComponent(pathParamFileId));
    
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
        result.Response200 = await Models.NewDownloadAttachmentBytesFederation200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewDownloadAttachmentBytesFederation400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewDownloadAttachmentBytesFederation401Response(response);
        break;
    
      case 403:
        result.Response403 = await Models.NewDownloadAttachmentBytesFederation403Response(response);
        break;
    
      case 404:
        result.Response404 = await Models.NewDownloadAttachmentBytesFederation404Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewDownloadAttachmentBytesFederation500Response(response);
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

    var path = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}";
    
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

    var path = "/iimp/api/federation/users/{userId}";
    
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
    
      case 400:
        result.Response400 = await Models.NewGetUserPublicKey400Response(response);
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
    
      case 400:
        result.Response400 = await Models.NewGetUserPublicKeyById400Response(response);
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

    var path = "/iimp/api/client/login";
    
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

    var path = "/iimp/api/client/logout";
    
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
    
      case 400:
        result.Response400 = await Models.NewLogout400Response(response);
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

    var path = "/iimp/api/federation/conversations/{conversationId}/messages";
    
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
  async NewConversation(params: Models.NewConversationRequest): Promise<NewConversationResult> {
    var result = {} as NewConversationResult;
    Models.ValidateNewConversationRequest(params);

    var path = "/iimp/api/client/conversations";
    
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

    var path = "/iimp/api/client/conversations/{conversationId}/messages";
    
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
  async PullUserEvents(params: Models.PullUserEventsRequest): Promise<PullUserEventsResult> {
    var result = {} as PullUserEventsResult;
    Models.ValidatePullUserEventsRequest(params);

    var path = "/iimp/api/client/events";
    
    const url = new URL(this.baseURL + path);
    
    var queryParamCursor = paramToString(params.Cursor, "query parameter: Cursor", "string", false);
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
        result.Response200 = await Models.NewPullUserEvents200Response(response);
        break;
    
      case 400:
        result.Response400 = await Models.NewPullUserEvents400Response(response);
        break;
    
      case 401:
        result.Response401 = await Models.NewPullUserEvents401Response(response);
        break;
    
      case 500:
        result.Response500 = await Models.NewPullUserEvents500Response(response);
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

    var path = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/react";
    
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
  async ReadMessage(params: Models.ReadMessageRequest): Promise<ReadMessageResult> {
    var result = {} as ReadMessageResult;
    Models.ValidateReadMessageRequest(params);

    var path = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/read";
    
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
  async RedactMessage(params: Models.RedactMessageRequest): Promise<RedactMessageResult> {
    var result = {} as RedactMessageResult;
    Models.ValidateRedactMessageRequest(params);

    var path = "/iimp/api/client/conversations/{conversationId}/messages/{messageId}/redact";
    
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
  async RefreshSession(params: Models.RefreshSessionRequest): Promise<RefreshSessionResult> {
    var result = {} as RefreshSessionResult;
    Models.ValidateRefreshSessionRequest(params);

    var path = "/iimp/api/client/refresh-session";
    
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
    
      case 400:
        result.Response400 = await Models.NewRefreshSession400Response(response);
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

    var path = "/iimp/api/client/request-reset-password";
    
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

    var path = "/iimp/api/client/reset-password";
    
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

    var path = "/iimp/api/client/signup";
    
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
    
      case 403:
        result.Response403 = await Models.NewSignUp403Response(response);
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
  async UpdateConversation(params: Models.UpdateConversationRequest): Promise<UpdateConversationResult> {
    var result = {} as UpdateConversationResult;
    Models.ValidateUpdateConversationRequest(params);

    var path = "/iimp/api/client/conversations/{conversationId}";
    
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

    var path = "/iimp/api/client/attachments";
    
    const url = new URL(this.baseURL + path);
    

    var requestInit: RequestInit = {
      method: "POST",
    }
    
    var headerFilename = paramToString(params.Filename, "header parameter: Filename", "string", true);
    requestInit.headers = { ...requestInit.headers, "X-IIMP-Attachment-Filename": headerFilename };
    
    
    const request = new Request(url, this.addHeaders(requestInit));
    const response = await fetch(request);
    result.StatusCode = response.status;
    switch (response.status) {
    
      case 201:
        result.Response201 = await Models.NewUploadAttachment201Response(response);
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


export type AddPublicKeyResult = {
  StatusCode: number;
  
  Response201: Models.AddPublicKey201Response;
  
  Response400: Models.AddPublicKey400Response;
  
  Response401: Models.AddPublicKey401Response;
  
  Response500: Models.AddPublicKey500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type ConversationFederationResult = {
  StatusCode: number;
  
  Response200: Models.ConversationFederation200Response;
  
  Response400: Models.ConversationFederation400Response;
  
  Response401: Models.ConversationFederation401Response;
  
  Response403: Models.ConversationFederation403Response;
  
  Response404: Models.ConversationFederation404Response;
  
  Response500: Models.ConversationFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type DiscoverServerResult = {
  StatusCode: number;
  
  Response200: Models.DiscoverServer200Response;
  
  Response404: Models.DiscoverServer404Response;
  
  Response500: Models.DiscoverServer500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type DownloadAttachmentResult = {
  StatusCode: number;
  
  Response200: Models.DownloadAttachment200Response;
  
  Response400: Models.DownloadAttachment400Response;
  
  Response401: Models.DownloadAttachment401Response;
  
  Response403: Models.DownloadAttachment403Response;
  
  Response404: Models.DownloadAttachment404Response;
  
  Response500: Models.DownloadAttachment500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type DownloadAttachmentBytesFederationResult = {
  StatusCode: number;
  
  Response200: Models.DownloadAttachmentBytesFederation200Response;
  
  Response400: Models.DownloadAttachmentBytesFederation400Response;
  
  Response401: Models.DownloadAttachmentBytesFederation401Response;
  
  Response403: Models.DownloadAttachmentBytesFederation403Response;
  
  Response404: Models.DownloadAttachmentBytesFederation404Response;
  
  Response500: Models.DownloadAttachmentBytesFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type EditMessageResult = {
  StatusCode: number;
  
  Response200: Models.EditMessage200Response;
  
  Response400: Models.EditMessage400Response;
  
  Response401: Models.EditMessage401Response;
  
  Response403: Models.EditMessage403Response;
  
  Response404: Models.EditMessage404Response;
  
  Response500: Models.EditMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type GetJWKSStoreResult = {
  StatusCode: number;
  
  Response200: Models.GetJWKSStore200Response;
  
  Response500: Models.GetJWKSStore500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type GetUserInfoFederationResult = {
  StatusCode: number;
  
  Response200: Models.GetUserInfoFederation200Response;
  
  Response401: Models.GetUserInfoFederation401Response;
  
  Response404: Models.GetUserInfoFederation404Response;
  
  Response500: Models.GetUserInfoFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type GetUserPublicKeyResult = {
  StatusCode: number;
  
  Response200: Models.GetUserPublicKey200Response;
  
  Response400: Models.GetUserPublicKey400Response;
  
  Response404: Models.GetUserPublicKey404Response;
  
  Response500: Models.GetUserPublicKey500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type GetUserPublicKeyByIdResult = {
  StatusCode: number;
  
  Response200: Models.GetUserPublicKeyById200Response;
  
  Response400: Models.GetUserPublicKeyById400Response;
  
  Response404: Models.GetUserPublicKeyById404Response;
  
  Response500: Models.GetUserPublicKeyById500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type LoginResult = {
  StatusCode: number;
  
  Response200: Models.Login200Response;
  
  Response400: Models.Login400Response;
  
  Response401: Models.Login401Response;
  
  Response500: Models.Login500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type LogoutResult = {
  StatusCode: number;
  
  Response204: Models.Logout204Response;
  
  Response400: Models.Logout400Response;
  
  Response401: Models.Logout401Response;
  
  Response500: Models.Logout500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type MessageFederationResult = {
  StatusCode: number;
  
  Response200: Models.MessageFederation200Response;
  
  Response400: Models.MessageFederation400Response;
  
  Response401: Models.MessageFederation401Response;
  
  Response403: Models.MessageFederation403Response;
  
  Response404: Models.MessageFederation404Response;
  
  Response500: Models.MessageFederation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type NewConversationResult = {
  StatusCode: number;
  
  Response201: Models.NewConversation201Response;
  
  Response400: Models.NewConversation400Response;
  
  Response401: Models.NewConversation401Response;
  
  Response403: Models.NewConversation403Response;
  
  Response404: Models.NewConversation404Response;
  
  Response500: Models.NewConversation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type NewMessageResult = {
  StatusCode: number;
  
  Response201: Models.NewMessage201Response;
  
  Response400: Models.NewMessage400Response;
  
  Response401: Models.NewMessage401Response;
  
  Response403: Models.NewMessage403Response;
  
  Response404: Models.NewMessage404Response;
  
  Response500: Models.NewMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type PullUserEventsResult = {
  StatusCode: number;
  
  Response200: Models.PullUserEvents200Response;
  
  Response400: Models.PullUserEvents400Response;
  
  Response401: Models.PullUserEvents401Response;
  
  Response500: Models.PullUserEvents500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type ReactToMessageResult = {
  StatusCode: number;
  
  Response200: Models.ReactToMessage200Response;
  
  Response400: Models.ReactToMessage400Response;
  
  Response401: Models.ReactToMessage401Response;
  
  Response403: Models.ReactToMessage403Response;
  
  Response404: Models.ReactToMessage404Response;
  
  Response500: Models.ReactToMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type ReadMessageResult = {
  StatusCode: number;
  
  Response200: Models.ReadMessage200Response;
  
  Response400: Models.ReadMessage400Response;
  
  Response401: Models.ReadMessage401Response;
  
  Response403: Models.ReadMessage403Response;
  
  Response404: Models.ReadMessage404Response;
  
  Response500: Models.ReadMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type RedactMessageResult = {
  StatusCode: number;
  
  Response200: Models.RedactMessage200Response;
  
  Response400: Models.RedactMessage400Response;
  
  Response401: Models.RedactMessage401Response;
  
  Response403: Models.RedactMessage403Response;
  
  Response404: Models.RedactMessage404Response;
  
  Response500: Models.RedactMessage500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type RefreshSessionResult = {
  StatusCode: number;
  
  Response200: Models.RefreshSession200Response;
  
  Response400: Models.RefreshSession400Response;
  
  Response401: Models.RefreshSession401Response;
  
  Response500: Models.RefreshSession500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type RequestResetPasswordResult = {
  StatusCode: number;
  
  Response200: Models.RequestResetPassword200Response;
  
  Response400: Models.RequestResetPassword400Response;
  
  Response500: Models.RequestResetPassword500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type ResetPasswordResult = {
  StatusCode: number;
  
  Response200: Models.ResetPassword200Response;
  
  Response401: Models.ResetPassword401Response;
  
  Response500: Models.ResetPassword500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type SignUpResult = {
  StatusCode: number;
  
  Response201: Models.SignUp201Response;
  
  Response400: Models.SignUp400Response;
  
  Response403: Models.SignUp403Response;
  
  Response409: Models.SignUp409Response;
  
  Response500: Models.SignUp500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type UpdateConversationResult = {
  StatusCode: number;
  
  Response200: Models.UpdateConversation200Response;
  
  Response400: Models.UpdateConversation400Response;
  
  Response401: Models.UpdateConversation401Response;
  
  Response403: Models.UpdateConversation403Response;
  
  Response404: Models.UpdateConversation404Response;
  
  Response500: Models.UpdateConversation500Response;
  
  UnknownResponse: UnknownStatusResponse;
}

export type UploadAttachmentResult = {
  StatusCode: number;
  
  Response201: Models.UploadAttachment201Response;
  
  Response400: Models.UploadAttachment400Response;
  
  Response401: Models.UploadAttachment401Response;
  
  Response403: Models.UploadAttachment403Response;
  
  Response404: Models.UploadAttachment404Response;
  
  Response413: Models.UploadAttachment413Response;
  
  Response500: Models.UploadAttachment500Response;
  
  UnknownResponse: UnknownStatusResponse;
}


export type UnknownStatusResponse = {
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


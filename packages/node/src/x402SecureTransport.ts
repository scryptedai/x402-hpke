import { CanonicalHeaders, HeaderEntry, TransportType } from "./constants.js";

function isObject(value: any): value is Record<string, any> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyObject(value: any): value is Record<string, any> {
  return isObject(value) && Object.keys(value).length > 0;
}

export class x402SecureTransport {
  private _headerCore: HeaderEntry | undefined;
  private _body: Record<string, any> = {};
  private _httpResponseCode: number | undefined;
  private _extensions: HeaderEntry[] = [];

  constructor(
    type: TransportType,
    content: Record<string, any> = {},
    httpResponseCode?: number,
    extensions?: HeaderEntry[]
  ) {
    if (!isObject(content)) {
      throw new Error("CONTENT_OBJECT");
    }
    this._extensions = Array.isArray(extensions) ? extensions : [];

    switch (type) {
      case "OTHER_REQUEST": {
        if (httpResponseCode !== undefined) throw new Error("OTHER_REQUEST_HTTP_CODE");
        this._body = content;
        break;
      }
      case "OTHER_RESPONSE": {
        if (httpResponseCode === 402) throw new Error("OTHER_RESPONSE_402");
        this._httpResponseCode = httpResponseCode;
        this._body = content;
        break;
      }
      case "PAYMENT_REQUIRED": {
        if (!isNonEmptyObject(content)) throw new Error("PAYMENT_REQUIRED_CONTENT");
        if (httpResponseCode !== undefined && httpResponseCode !== 402) {
          console.warn("PAYMENT_REQUIRED_HTTP_CODE_WARN: Coercing to 402");
        }
        this._httpResponseCode = 402;
        this._body = content;
        break;
      }
      case "PAYMENT_RESPONSE": {
        if (!isNonEmptyObject(content)) throw new Error("PAYMENT_RESPONSE_CONTENT");
        if (httpResponseCode !== undefined && httpResponseCode !== 200) {
          throw new Error("PAYMENT_RESPONSE_HTTP_CODE");
        }
        this._httpResponseCode = 200;
        this._headerCore = { header: CanonicalHeaders.X_PAYMENT_RESPONSE, value: content };
        this._body = {};
        break;
      }
      case "PAYMENT": {
        if (httpResponseCode !== undefined) throw new Error("PAYMENT_HTTP_CODE");
        if (!("payload" in content)) throw new Error("PAYMENT_PAYLOAD");
        this._headerCore = { header: CanonicalHeaders.X_PAYMENT, value: content };
        this._body = {};
        break;
      }
      default: {
        const _exhaustive: never = type as never;
        throw new Error(`UNSUPPORTED_TYPE:${_exhaustive}`);
      }
    }
  }

  getHeader(): HeaderEntry | undefined {
    return this._headerCore;
  }

  getBody(): Record<string, any> {
    return this._body;
  }

  getExtensions(): HeaderEntry[] {
    return this._extensions;
  }

  getHttpResponseCode(): number | undefined {
    return this._httpResponseCode;
  }
}

export type { TransportType };



export class HttpError extends Error {
  public readonly statusCode: number;

  public readonly code: string;

  public constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

export const isHttpError = (error: unknown): error is HttpError => error instanceof HttpError;

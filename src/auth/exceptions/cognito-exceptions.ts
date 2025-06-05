export class CognitoException extends Error {
    constructor(
      public readonly message: string,
      public readonly statusCode: number,
      public readonly errorCode: string,
    ) {
      super(message);
      this.name = 'CognitoException';
    }
  }
  
  // Common Cognito error types
  export class UserNotFoundException extends CognitoException {
    constructor() {
      super('User does not exist', 404, 'USER_NOT_FOUND');
    }
  }
  
  export class UserNotConfirmedException extends CognitoException {
    constructor() {
      super('User is not confirmed', 400, 'USER_NOT_CONFIRMED');
    }
  }
  
  export class InvalidPasswordException extends CognitoException {
    constructor() {
      super('Password does not conform to policy', 400, 'INVALID_PASSWORD');
    }
  }
  
  export class NotAuthorizedException extends CognitoException {
    constructor(message = 'Incorrect username or password') {
      super(message, 401, 'NOT_AUTHORIZED');
    }
  }
  
  export class UsernameExistsException extends CognitoException {
    constructor() {
      super('Username already exists', 409, 'USERNAME_EXISTS');
    }
  }
  
  export class CodeMismatchException extends CognitoException {
    constructor() {
      super('Invalid verification code', 400, 'CODE_MISMATCH');
    }
  }
  
  export class ExpiredCodeException extends CognitoException {
    constructor() {
      super('Verification code has expired', 400, 'EXPIRED_CODE');
    }
  }
  
  export class LimitExceededException extends CognitoException {
    constructor() {
      super('Attempt limit exceeded, please try again later', 429, 'LIMIT_EXCEEDED');
    }
  }
  
  export class TooManyRequestsException extends CognitoException {
    constructor() {
      super('Too many requests, please try again later', 429, 'TOO_MANY_REQUESTS');
    }
  }
  
  export class InvalidParameterException extends CognitoException {
    constructor(message = 'Invalid parameter') {
      super(message, 400, 'INVALID_PARAMETER');
    }
  }
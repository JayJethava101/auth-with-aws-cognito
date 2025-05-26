import { 
    ArgumentsHost, 
    Catch, 
    ExceptionFilter, 
    HttpException, 
    HttpStatus, 
    Logger 
  } from '@nestjs/common';
  import { Request, Response } from 'express';
  import { 
    CognitoException, 
    UserNotFoundException, 
    UserNotConfirmedException, 
    InvalidPasswordException, 
    NotAuthorizedException, 
    UsernameExistsException, 
    CodeMismatchException, 
    ExpiredCodeException, 
    LimitExceededException, 
    TooManyRequestsException,
    InvalidParameterException
  } from './cognito-exceptions';
  
  @Catch()
  export class CognitoExceptionFilter implements ExceptionFilter {
    private readonly logger = new Logger(CognitoExceptionFilter.name);
  
    catch(exception: unknown, host: ArgumentsHost) {
      const ctx = host.switchToHttp();
      const response = ctx.getResponse<Response>();
      const request = ctx.getRequest<Request>();
  
      let status: number = HttpStatus.INTERNAL_SERVER_ERROR;
      let errorResponse = {
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        message: 'Internal server error',
        errorCode: 'INTERNAL_ERROR',
      };
      
  
      // Check if it's a cognito-specific exception
      if (exception instanceof CognitoException) {
        console.log('---> The error captured in cognito-specific exception')
        status = exception.statusCode;
        errorResponse = {
          ...errorResponse,
          statusCode: status,
          message: exception.message,
          errorCode: exception.errorCode,
        };
      }
      // Handle NestJS HTTP exceptions 
      else if (exception instanceof HttpException) {
       console.log('---> The error captured in NestJS HTTP exceptions')

        status = exception.getStatus();
        const exceptionResponse = exception.getResponse();
 
        errorResponse = {
          ...errorResponse,
          statusCode: status,
          message: typeof exceptionResponse === 'object' 
            ? (exceptionResponse as any).message || 'Http exception'
            : exceptionResponse,
          errorCode: 'HTTP_ERROR',
        };
      } 
      // Handle AWS SDK exceptions and map them to our custom exceptions
      else if (typeof exception === 'object' && exception !== null && 'constructor' in exception) {
        console.log('---> The error captured in AWS SDK exceptions')

        if (exception.constructor.name === 'UserNotFoundException') {
          const cognitoError = new UserNotFoundException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'UserNotConfirmedException') {
          const cognitoError = new UserNotConfirmedException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'InvalidPasswordException') {
          const cognitoError = new InvalidPasswordException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'NotAuthorizedException') {
          const cognitoError = new NotAuthorizedException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: (exception as { message: string, staus: number })?.message || cognitoError.message,
            errorCode: cognitoError.errorCode,
          
          
          };
        } else if (exception.constructor.name === 'UsernameExistsException') {
          const cognitoError = new UsernameExistsException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'CodeMismatchException') {
          const cognitoError = new CodeMismatchException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'ExpiredCodeException') {
          const cognitoError = new ExpiredCodeException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'LimitExceededException') {
          const cognitoError = new LimitExceededException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'TooManyRequestsException') {
          const cognitoError = new TooManyRequestsException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        } else if (exception.constructor.name === 'InvalidParameterException') {
          const cognitoError = new InvalidParameterException();
          status = cognitoError.statusCode;
          errorResponse = {
            ...errorResponse,
            statusCode: status,
            message: cognitoError.message,
            errorCode: cognitoError.errorCode,
          };
        }
      }
     
  
      // Log the error (but not in production for sensitive info)
      this.logger.error(`${request.method} ${request.url} ${status}`, exception);
  
      // Send the error response
      response.status(status).json(errorResponse);
    }
  }
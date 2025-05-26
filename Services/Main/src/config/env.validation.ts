import { plainToInstance } from 'class-transformer';
import { IsNumber, IsString, validateSync } from 'class-validator';

export class EnvironmentVariables {
  @IsString()
  PG_HOST: string;

  @IsNumber()
  PG_PORT: number;

  @IsString()
  PG_USER: string;

  @IsString()
  PG_PASSWORD: string;

  @IsString()
  PG_MANAGEMENT_DB: string;
}


export function validate(config: Record<string, unknown>) {
    const validatedConfig = plainToInstance(
      EnvironmentVariables,
      config,
      { enableImplicitConversion: true },
    );
    const errors = validateSync(validatedConfig, { skipMissingProperties: false });
  
    if (errors.length > 0) {
      throw new Error(errors.toString());
    }
    return validatedConfig;
  }
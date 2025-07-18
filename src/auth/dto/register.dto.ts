// import {IsEmail , IsNotEmpty,IsString,MinLength} from 'class-validator'

// controller kajbaki 

export class RegisterDto{
    @IsEmail()
    @IsNotEmpty()
    email:string;

    @IsString()
    @IsNotEmpty()
    @MinLength(6)
    password:string;
    
    @IsString()
    @IsNotEmpty()
    firstName:string;

    @IsString()
    @IsNotEmpty()
    lastName:string;

    @IsString()
    @IsNotEmpty()
    role:string;

}
import {
  Controller,
  Get,
  Response,
  HttpStatus,
  Param,
  Body,
  Post,
  Request,
  Patch,
  Delete,
  Render
} from "@nestjs/common";
import { Utility } from ".././common/utility";
import { ResMessage } from ".././common/res.message";
import { ApiUseTags, ApiResponse, ApiBearerAuth } from "@nestjs/swagger";
import { checkCollectionNameDto } from "./dto/gii.dto";
import * as fs from 'fs';
 
@ApiUseTags("gii")
@Controller("gii")
export class GiiController {
    constructor(private readonly Utility: Utility) {}
    
  @Get()
  @Render('index')
  root() {
    return { message: 'Hello world!' };
  }
  
  @Post()
  public async login(
      @Response() res,
      @Request() req,
      @Body() checkCollectionNameDto: checkCollectionNameDto
      ) {
      try {
            
      return this.Utility.sendSucc(req,res,{"token":""},ResMessage.LOGIN_SUCC);
      
      
      } catch (e){
      return this.Utility.sendErr(req,res,e);
      }
  }
  
   @Post("/createFiles")
  public async createFiles(
      @Response() res,
      @Request() req,
      @Body() checkCollectionNameDto: checkCollectionNameDto
      ) {
      try {
 

function createFile(path,collectionName,fileName,cont){
    return new Promise(function (resolve, reject) {
        console.log(path+'/'+collectionName+fileName,"ok");
     fs.writeFile(path+'/'+collectionName+fileName, cont, function (err) {
  if (err) throw reject(err);
  resolve("ok");
});  
     });
}

function createFileWithFolder(path,collectionName,fileName,cont,folderName){
    return new Promise(function (resolve, reject) {
        fs.mkdir(path+"/"+folderName, async (err) => {  if (err) {
            reject(err);
        } else { 
     fs.writeFile(path+"/"+folderName+"/"+collectionName+fileName, cont, function (err) {
  if (err) throw reject(err);
  console.log("call");
  resolve("ok");
        
});  }  });
     });
}

function readFile(path){
    return new Promise(function (resolve, reject) {
        fs.readFile(path, {encoding: 'utf-8'}, function(err,data){
  if (err) throw reject(err);
  resolve(data);
});  
     });
}

function escapeRegExp(string){
    return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function replaceAll(str, term, replacement) {
  return str.replace(new RegExp(escapeRegExp(term), 'g'), replacement);
}

 function ensureExists(path,collectionName,collectionNameC,checkCollectionNameDto)  {
    return new Promise(function (resolve, reject) {
        fs.mkdir(path, async (err) => {
        if (err) {
            reject(err);
        } else {

        let cont = await readFile(__dirname+"/template/name.controller.spec.ts");
        var newStr = replaceAll(cont, 'name', collectionName);
        var newStr1 = replaceAll(newStr, 'Name', collectionNameC);
        await createFile(path,collectionName,'.controller.spec.ts',newStr1);
        
        let contA = await readFile(__dirname+"/template/name.controller.ts");
        var newStrA = replaceAll(contA, 'name', collectionName);
        var newStrA1 = replaceAll(newStrA, 'Name', collectionNameC);
        
        let fieldReplace="";
         for(let i in checkCollectionNameDto.field_name) {
             fieldReplace = collectionName + "Data."+checkCollectionNameDto.field_name[i]+" = UpdateDto."+checkCollectionNameDto.field_name[i]+"; \n\ " + fieldReplace;
         }
        newStrA1 = replaceAll(newStrA1, 'fieldReplace',fieldReplace );
        
        await createFile(path,collectionName,'.controller.ts',newStrA1);
        
        let contB = await readFile(__dirname+"/template/name.module.ts");
        var newStrB = replaceAll(contB, 'name', collectionName);
        var newStrB1 = replaceAll(newStrB, 'Name', collectionNameC);
        var newStrB2 = replaceAll(newStrB1, 'mongooseN', 'name');
        await createFile(path,collectionName,'.module.ts',newStrB2);
        
        let contC = await readFile(__dirname+"/template/name.service.ts");
        var newStrC = replaceAll(contC, 'name', collectionName);
        var newStrC1 = replaceAll(newStrC, 'Name', collectionNameC);
        await createFile(path,collectionName,'.service.ts',newStrC1);
        
        
        let folderName="dto";
        let contD = await readFile(__dirname+"/template/"+folderName+"/name.dto.ts");
        var newStrD = replaceAll(contD, 'name', collectionName);
        let newStrD1 = replaceAll(newStrD, 'Name', collectionNameC);
        
         fieldReplace="";
         for(let i in checkCollectionNameDto.field_name) {
             let field_type_mod = "number";
             if(checkCollectionNameDto.field_type[i]=="String") {
                 field_type_mod ="string";
             } 
             fieldReplace = "@ApiModelProperty() \n\ readonly "+checkCollectionNameDto.field_name[i]+": "+field_type_mod+"; \n\ \n\ " + fieldReplace;
         }
        newStrD1 = replaceAll(newStrD1, 'fieldReplace',fieldReplace );
        await createFileWithFolder(path,collectionName,'.dto.ts',newStrD1,folderName);
        
        folderName="interfaces";
        let contE = await readFile(__dirname+"/template/"+folderName+"/iname.service.ts");
        var newStrE = replaceAll(contE, 'name', collectionName);
        var newStrE1 = replaceAll(newStrE, 'Name', collectionNameC);
        await createFileWithFolder(path,"i"+collectionName,'.service.ts',newStrE1,folderName);
        
         contC = await readFile(__dirname+"/template/interfaces/name.interface.ts");
         newStrC = replaceAll(contC, 'name', collectionName);
         newStrC1 = replaceAll(newStrC, 'Name', collectionNameC);
          fieldReplace="";
         for(let i in checkCollectionNameDto.field_name) {
             let field_type_mod = "number";
             if(checkCollectionNameDto.field_type[i]=="String") {
                 field_type_mod ="string";
             } 
             fieldReplace = checkCollectionNameDto.field_name[i]+": "+field_type_mod+"; \n\ " + fieldReplace;
         }
        newStrC1 = replaceAll(newStrC1, 'fieldReplace',fieldReplace );
        await createFile(path+"/interfaces",collectionName,'.interface.ts',newStrC1);
        
        folderName="schemas";
         contE = await readFile(__dirname+"/template/"+folderName+"/name.schema.ts");
         newStrE = replaceAll(contE, 'name', collectionName);
         newStrE1 = replaceAll(newStrE, 'Name', collectionNameC);
         
          fieldReplace="";
         
         for(let i in checkCollectionNameDto.field_name) {
             if(checkCollectionNameDto.field_name[i]==false) {
             fieldReplace = checkCollectionNameDto.field_name[i] + ": { type : " + checkCollectionNameDto.field_type[i] + " },\n\ " + fieldReplace
             } else {
             fieldReplace = checkCollectionNameDto.field_name[i] + ": { type : " + checkCollectionNameDto.field_type[i] + ", required : true }, \n\ " + fieldReplace    
             }
         }
         fieldReplace = fieldReplace.slice(0, fieldReplace.length-1);
         newStrE1 = replaceAll(newStrE1, 'fieldReplace',fieldReplace );
        await createFileWithFolder(path,collectionName,'.schema.ts',newStrE1,folderName);
        
           resolve('ok');
         }; // successfully created folder
    });
    });
}

let collectionName = checkCollectionNameDto.name;
let collectionNameC = collectionName.charAt(0).toUpperCase() + collectionName.slice(1);
let path = __dirname + '/../'+collectionName;
await ensureExists(path,collectionName,collectionNameC,checkCollectionNameDto);



 
// writeFile function with filename, content and callback function

            
      return this.Utility.sendSucc(req,res,{"token":""},ResMessage.LOGIN_SUCC);
      
      
      } catch (e){ 
      return this.Utility.sendErr(req,res,e);
      }
  }
  
  }
      


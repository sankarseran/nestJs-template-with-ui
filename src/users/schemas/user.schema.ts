import * as mongoose from "mongoose";
import * as passportLocalMongoose from "passport-local-mongoose";


export enum role {
    USER = 'user',
    ADMIN = 'admin',
    SUPER_ADMIN = 'super_admin',
}


var validateEmail = function(email) {
    var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

export const UserSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: {
        type: String,
        trim: true,
        lowercase: true,
        unique: true,
        required: 'Email address is required',
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
  password: String,
  forget_password_token: String,
  forget_password_expried_time: Date,
  created_date_time: {type: Date},
  role: {type: String, enum: [role.USER, role.ADMIN, role.SUPER_ADMIN]}
}); 
//UserSchema.plugin(passportLocalMongoose);


//const connection = mongoose.connection;
//Object.keys(connection).forEach((collection) => {
//  // You can get the string name.
//  console.info(collection.collections);
//  // Or you can do something else with the model.
//  
//});




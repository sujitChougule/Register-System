import express from 'express';
import path from 'path';
import mongose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
const app =express();



//db
const userShcema=new mongose.Schema({
    name:String,
    email:String,
    password:String
})

const User = mongose.model("User",userShcema);

mongose.connect("mongodb://localhost:27017",{dbName:"backend"}).then(()=>{
    console.log("db connected"); 
}).catch((e)=>{
    console.log(e);
});

//routes
app.use(cookieParser());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(path.resolve(),"public")));
app.set("view engine","ejs");


//server connection
app.listen(5000,()=>{
    console.log("server is running at port 5000")
})  

// //logout long in

const isauthenticated=async(req,res,next)=>{
    const {token}=req.cookies;
    if(token){
        //
        const decoded =jwt.verify(token,"usnefvius");
        req.user =await User.findById(decoded._id);


        next();
    }else{
        res.redirect("/login");
    }
};

app.get('/' ,isauthenticated ,(req,res)=>{
    console.log(req.user);
    res.render('logout',{name:req.user.name});
});

app.get('/login',(req,res)=>{
    res.render("login")
})

app.post('/login',async(req,res)=>{
    const {email,password}= req.body;
    let user =await User.findOne({email});
    if(!user) return res.redirect("/register");

    const isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch) 
        return res.render("login",{email,message:"Incorrect Passsword"});

    //securing token value using jsonWebToken
    const token =jwt.sign({_id:user._id,},"usnefvius");
    //
    //adding cookie
    res.cookie("token", token,{
        httpOnly:true,
    });
    res.redirect("/");

    
});

app.get("/logout",(req,res)=>{
    //removing cookie
    res.cookie("token", null,
    {expires:new Date(Date.now()),});
    res.redirect("/");
})

//register

app.get("/register",(req,res)=>{
    res.render("register")
})
    
    
app.post('/register',async(req,res)=>{
        const {name, email,password}=req.body;
        
        let user= await User.findOne({email});
        if(user){
            return res.redirect("/login");
        }
    
        //hashing password
        const hashPassword =await bcrypt.hash(password,10);


        //console.log(req.body);
         user=await User.create({
            name,
            email,
            password:hashPassword,
        });
    
    
        //securing token value using jsonWebToken
        const token =jwt.sign({_id:user._id,},"usnefvius");
        //
        //adding cookie
        res.cookie("token", token);
        res.redirect("/");
});

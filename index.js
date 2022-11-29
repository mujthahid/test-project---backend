
const express = require('express')
const app = express()
const mysql = require('mysql2')
const cors = require('cors')
const bcrypt = require('bcrypt')
const saltRounds = 10;
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const session = require('express-session')


const db = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"password",
    database:"userDB",

})

db.connect((err)=>{
if (err) throw err;
console.log("db connected successfully")
})
app.set('trust proxy',true)
app.use(express.json())
app.use(cors({
    origin:["http://localhost:3000"],
    methods:["GET","POST","PATCH","DELETE"],
    credentials:true
}))

app.use(cookieParser())
app.use(bodyParser.urlencoded({extended:true}))
app.listen(3001,(err)=>{
    if (err) throw err;
    else{
        console.log("server started successfully")
    }
})
app.use(session({
    secret:"mysecretcode",
    resave:false,
    saveUninitialized:true,
    cookie:{
        maxAge:1000 * 60 * 60 * 24,
    }
}))

app.get('/login',(req,res)=>{
    
if(req.session.user){
    res.send({loggedIn:true,user:req.session.user})
}else{
    res.send({loggedIn:false})
}
})

app.post('/login',(req,res)=>{
    const email = req.body.email;
    const password = req.body.password;
    const ip = req.ip
    const time = Date.now()

    db.query('SELECT COUNT(*) AS COUNT FROM login_attempts WHERE ip =(?)',[ip],(err,result)=>{
        if(err){
            console.log=(err)
        }else{
          if(result[0].COUNT <= 4) {

            db.query('SELECT * FROM users WHERE email = (?)',[email],async(err,reslt) => {
                if(!err){
                    if(reslt.length>0){
                     let encryptedPassword = reslt[0].password;
                    const comparison = await bcrypt.compare(password,encryptedPassword)
                    if(comparison){
                        req.session.user = {username:reslt[0].username,email:reslt[0].email}
                    db.query('DELETE FROM login_attempts WHERE ip =(?)',[ip],(err,resp)=>{
                            if(err)console.log(err)
                            else console.log(resp)
                        })
                        res.send({success:true})
                    }
                    else{
                        db.query('INSERT INTO login_attempts (ip,time) VALUES (?,?)',[ip,time],(err,rows,fields)=>{
                            if(err){
                                console.log(err)
                            }else{
                                console.log(rows)
                            }
                        })
                        res.send({error:"Incorrect email or password"})
                    }
                }else{
                    db.query('INSERT INTO login_attempts (ip,time) VALUES (?,?)',[ip,time],(err,rows,fields)=>{
                        if(err){
                            console.log(err)
                        }else{
                            console.log(rows)
                        }
                    })
                    res.send({error:"Incorrect email or password"})
                }
                   }
            })
}
if(result[0].COUNT >4){
    db.query('SELECT MAX(time) AS LAST_ATTEMPT FROM login_attempts WHERE ip=(?)',[ip],(err,value)=>{
        if(err)console.log(err)
        else {
           if((Date.now()-value[0].LAST_ATTEMPT)>1000*60*60*24){
            db.query('DELETE FROM login_attempts WHERE ip = (?)',[ip],(err,results)=>{
                if(err)console.log(err)
                else console.log(results)
            })
           }
        }
    })
    res.send({error:"Too many attempts, try after sometime"})
}
            
        }
    })
    
 


})

app.get('/userData',(req,res)=>{

    db.query("SELECT * FROM users",(err,result)=>{
        if(err) throw err;
    else{
        res.send(result)
    }
    })

})

app.delete('/users/:id',(req,res)=>{
    let id = req.params.id;
db.query('DELETE FROM users WHERE id = (?)',id,(err,rows,fields)=>{
    if(!err){
        console.log(rows)
        res.send({success:true})
    }
    else{
        console.log(err);
       }
})
    
})

app.patch('/updateUser',async(req,res)=>{
    
    let username = req.body.username;
    let password = req.body.password;
    let encryptedPassword = await bcrypt.hash(password,saltRounds)
    let id = req.body.id;
    db.query("UPDATE users SET username = (?) , password = (?) WHERE id = (?) ",[username,encryptedPassword,id],(err,rows,fields)=>{
        if(!err){
            console.log(rows)
            res.send({success:true})
        }
        else console.log(err)
    })
   
})

app.post('/addUser',async(req,res)=> {

    let username = req.body.username;
    let email = req.body.email;
    let password = req.body.password;
    let confirmPassword = req.body.confirmPassword

    if (password===confirmPassword){
  
    let encryptedPassword = await bcrypt.hash(password,saltRounds)

    db.query('INSERT INTO users (username,email,password) VALUES (?,?,?)',[username,email,encryptedPassword],(err,rows,fields)=>{
            if(!err) {
            console.log(rows)
           res.send({success:true})
}
else {
    console.log(err)
    if(err.errno== 1062){
        res.json({error:"Email already exists"})
    }
}
            
    })
}else{
    res.send({error:"Password and Confirm Password should be same"})
}
})

app.get("/logout",(req,res)=> {
    req.session.destroy()
    res.send({success:true})
})
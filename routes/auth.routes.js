const router = require('express').Router();
const userModel = require('../models/User.model')
const bcrypt = require('bcryptjs');
const session = require('express-session');  //do we need to do that?
const MongoStore = require('connect-mongo');

//sign up  - info
router.get('/signup', (req, res, next) =>{
    res.render('auth/signup.hbs')
})

router.post('/signup', (req, res, next) => {
    const {username, password} = req.body
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    console.log(password)

    if(!username || !password){
        res.render('auth/signup', {error: "plz fill in all fields"})
        return;
    }

    const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{6,16}$/
    if(!passwordRegex.test(password)){
        res.render('auth/signup', {error: "invalid password, pick another one plz"})
        return;
    }
    
    userModel.findOne({username})
    .then((user) => {
       if (user){
        res.render('auth/signup', {error: "pick another username"})
       }
    })
    .catch((err) => {
        next(err)
    })      
    userModel.create({username, password: hash})
        .then(() => {
            res.redirect('/')
        })
        .catch((err) => {
            next(err)
    })
})

//sign in 
router.get('/signin', (req, res, next) => {
    res.render('auth/signin.hbs')
})

router.post('/signin', (req, res, next) =>{
    const {username, password} = req.body

    userModel.findOne({username})
        .then((user) => {
            if(user){
                let isValid = bcrypt.compareSync(password, user.password);
                if (isValid) {
                    req.session.loggedInUser = user
                    res.app.locals.isLoggedIn = true
                    res.redirect('/main')
                    console.log("ENTER")
                }  
            }
            else
                res.render('auth/signin', {error: 'Invalid password'})
        })
        .catch((err) =>{
            next(err)
        })
})
router.get('/main', (req, res, next) =>{
    res.render('auth/main')
})


//   log out 

router.get('/logout', (req, res, next) =>{
    res.app.locals.isLoggedIn = false
    req.session.destroy()
    res.redirect('/')
})

// costum middleware 
function checkLoggedIn(req, res, next){
  if ( req.session.loggedInUser) {
      next()
  }
  else{
    res.redirect('/signin')
  }
}


router.get('/main', checkLoggedIn, (req, res, next) => {
    res.render('auth/main.hbs', {name: req.session.loggedInUser.username})
})
router.get('/private', checkLoggedIn, (req, res, next) => {
    res.render('auth/private.hbs', {name: req.session.loggedInUser.username})
})



module.exports = router;



var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var passport = require('passport');
var bcrypt = require('bcrypt');
const saltRounds = 10;

/* GET home page. */
router.get('/', function(req, res, next){
  console.log(req.user);
  console.log(req.isAuthenticated());
  res.render('home', {title: 'Home'});
});

router.get('/profile', authenticationMiddleware(), function(req, res, next){
  res.setHeader("Content-Type", "text/html");
  res.render('profile', {title: 'Profile'});
});

router.get('/login', function(req, res){
  res.render('login', {title: 'Login'});
})

router.get('/logout', function(req, res){
  req.logout();
  req.session.destroy();
  res.redirect('/');
})

router.get('/register', function(req, res, next) {
  res.render('register', { title: 'Registration' });
});

router.post('/login', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/login'
}));

router.post('/register', function(req, res, next){
  req.checkBody('username', "Username filed cann't be empty").notEmpty();
  req.checkBody('email', "Email filed cann't be empty").isEmail();
  req.checkBody('password', "password filed cann't be empty").notEmpty();
  req.checkBody('passwordMatch', "password doesn't match").equals(req.body.password);
  const errors = req.validationErrors();
  if(errors){
    console.log(`errors: ${JSON.stringify(errors)}`);
    res.render('register', {
      title: 'Registration Error',
      errors: errors
    });
  }
  else {
    const username  = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    const db = require("../db.js");
    bcrypt.hash(password, saltRounds, function(err, hash) {
      db.query("insert into users(username, email, password) values(?,?,?)",[username,email,hash],
      function(error, result, field){
        if (error) throw error;

      db.query('SELECT LAST_INSERT_ID() AS user_id', function(error, results, fields){
        if (error) throw error;
        const user_id = results[0];
        req.login(user_id, function(err){
          res.redirect('/');
        })
      })
        res.render('register', {title: "Registration Completed"})
      })
    });

  }

})
passport.serializeUser(function(user_id, done) {
  done(null, user_id);
});

passport.deserializeUser(function(user_id, done) {
    done(null, user_id);
});

function authenticationMiddleware(){
  return (req, res, next) => {
    console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);
    if (req.isAuthenticated()){
      res.render('profile');
      return next;
    }
    res.redirect('/login')
  }
};
module.exports = router;

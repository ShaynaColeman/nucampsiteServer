const express = require('express');
const User = require('../models/user');
const passport = require('passport');
const authenticate = require('../authenticate')


const router = express.Router();

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post('/signup', (req, res) =>{//user is requesting to sign up
  User.register(
    new User({username: req.body.username}),
    req.body.password,
    (err, user) => {
      if (err) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.json({err: err});
      } else {
          if (req.body.firstname) {
              user.firstname = req.body.firstname;
          }
          if (req.body.lastname) {
              user.lastname = req.body.lastname;
          }
          user.save(err => {
              if (err) {
                  res.statusCode = 500;
                  res.setHeader('Content-Type', 'application/json');
                  res.json({err: err});
                  return;
              }
              passport.authenticate('local')(req, res, () => {
                  res.statusCode = 200;
                  res.setHeader('Content-Type', 'application/json');
                  res.json({success: true, status: 'Registration Successful!'});
              });
          });
      }
  }
);
});


//passport.authenticate = middleware that enables passport authentication
router.post('/login', passport.authenticate('local'), (req, res) => {
  //just need to set up a response if login was successful
  //if any errors, passport would have taken care of it already
    const token = authenticate.getToken({_id: req.user._id});
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.json({success: true, token: token, status: 'You are successfully logged in!'});
});

router.get('/logout', (req, res, next) => {
  if (req.session) {
      req.session.destroy();//deleting session file on server side
      res.clearCookie('session-id');//clear the cookie that's been stored on the client
      res.redirect('/');//redirects user to root path localhost3000/
  } else {
      const err = new Error('You are not logged in!');
      err.status = 401;
      return next(err);
  }
});


module.exports = router;

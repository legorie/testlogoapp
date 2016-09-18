var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var config = require('../oauth.js');
var GoogleStrategy = require('passport-google-oauth2').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;

var User = require('../models/user');

// Register
router.get('/register', function(req, res){
	res.render('register');
});

// Login
router.get('/login', function(req, res){
	res.render('login');
});

router.get('/auth/google',
  passport.authenticate('google', { scope: [
    'https://www.googleapis.com/auth/plus.login',
    'https://www.googleapis.com/auth/plus.profile.emails.read'
  ] }
));
router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/');
  });

router.get('/auth/facebook', passport.authenticate('facebook', { scope : 'email' }));

router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/'}),
  function(req, res) {
    res.redirect('/');
  });


// Register User
router.post('/register', function(req, res){
	var name = req.body.name;
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation
	req.checkBody('name', 'Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('username', 'Username is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);


	var errors = req.validationErrors();
	console.log(errors);

	if(errors){
		res.render('register',{
			errors:errors
		});
	} else {
		var newUser = new User({
			name: name,
			email:email,
			username: username,
			password: password,
			src: 'tt',
			created: Date.now()
		});

		User.createUser(newUser, function(err, user){
			if(err) throw err;
			console.log(user);
		});

		req.flash('success_msg', 'You are registered and can now login');

		res.redirect('/users/login');
	}
});

passport.use(new LocalStrategy(
  function(username, password, done) {
   User.getUserByUsername(username, function(err, user){
   	if(err) throw err;
   	if(!user){
   		return done(null, false, {message: 'Unknown User'});
   	}

   	User.comparePassword(password, user.password, function(err, isMatch){
   		if(err) throw err;
   		if(isMatch){
   			return done(null, user);
   		} else {
   			return done(null, false, {message: 'Invalid password'});
   		}
   	});
   });
  }));

//facebook
passport.use(new FacebookStrategy({
  clientID: config.facebook.clientID,
  clientSecret: config.facebook.clientSecret,
  callbackURL: config.facebook.callbackURL,
 	profileFields: ['emails','displayName']
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOne({ oauthID: profile.id }, function(err, user) {
      if(err) {
        console.log(err);  // handle errors!
      }
      if (!err && user !== null) {
        done(null, user);
      } else {
				if (profile.emails) {
					console.log(profile.emails);
					email_val = profile.emails[0].value;
				} else {
					console.log("Email field is empty; user not authorising");
					email_val = null;
				}
        user = new User({
          oauthID: profile.id,
          name: profile.displayName,
					// email: profile.email,
					email: email_val,
					src: 'fb',
          created: Date.now()
        });
        user.save(function(err) {
          if(err) {
            console.log(err);  // handle errors!
          } else {
            console.log("saving user ...");
            done(null, user);
          }
        });
      }
    });
  }
));


// Google
passport.use(new GoogleStrategy({
  clientID: config.google.clientID,
  clientSecret: config.google.clientSecret,
  callbackURL: config.google.callbackURL,
  passReqToCallback: true
  },
	function(request, accessToken, refreshToken, profile, done) {
		User.findOne({ oauthID: profile.id }, function(err, user) {
			if(err) {
				console.log(err);  // handle errors!
			}
			if (!err && user !== null) {
				done(null, user);
			} else {
				user = new User({
					oauthID: profile.id,
					name: profile.displayName,
					email: profile.email,
					src: 'goog',
					created: Date.now()
					//todo: hope to idenfiy the Oauth provider with the oauthID
				});
				user.save(function(err) {
					if(err) {
						console.log(err);  // handle errors!
					} else {
						console.log("saving user ...");
						done(null, user);
					}
				});
			}
		});
	}
));


passport.serializeUser(function(user, done) {
	console.log("serialize");
	console.log(user);
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
	console.log("deserialize");
	console.log(id);
  User.getUserById(id, function(err, user) {
		if(!err) done(null, user);
		else done(err, null);
  });
});

router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login',failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout', function(req, res){
	req.logout();

	req.flash('success_msg', 'You are logged out');

	res.redirect('/users/login');
});

module.exports = router;

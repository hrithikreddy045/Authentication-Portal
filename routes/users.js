const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

// User Model
const User = require('../models/User');

router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/register', (req, res) => {
    res.render('register');
});

// Register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    // Check all Fields
    if(!name || !email || !password || !password2) {
        errors.push({ msg : 'Please fill in all fields' });
    }

    // Check Passwords Match
    if(password !== password2) {
        errors.push({ msg : 'Passwords do not match' });
    }

    // Check Password Length
    if(password.length < 6 || password2.length < 6) {
        errors.push({ msg : 'Password should be atleast 6 characters' });
    }

    if(errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // Validation Passed - Now go for checking if the user is already registered!
        User.findOne({ email: email })
        .then(user => {
            if(user) {
                // User exists
                errors.push({ msg: 'Email is already registered' });
                res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else {
                const newUser = new User({
                    name,
                    email,
                    password
                });
                // Hash Password
                bcrypt.genSalt(10, (err, salt) => 
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;
                        // Set Password to Hash
                        newUser.password = hash;
                        // Save User
                        newUser.save()
                        .then(user => {
                            req.flash('success_msg', 'You are now registered an can Login');
                            res.redirect('/users/login');
                        })
                        .catch(err => console.log(err));
                    }));
            }
        });
    }

});

// Login Handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

// Logout Handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are now logged out');
    res.redirect('/users/login');
});

module.exports = router;
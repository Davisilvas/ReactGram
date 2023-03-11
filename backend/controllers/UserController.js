// Models
const User = require("../models/User");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose")
//const { default: mongoose } = require("mongoose");
const jwtSecret = process.env.JWT_SECRET;

// Generate User Token
const generateToken = ( id ) => {
    return jwt.sign({ id }, jwtSecret, {
        expiresIn: "7d",
    }); 
};

// Register User and sign In
const register = async (req, res) => {
    
    const { name, email, password } = req.body

    //check if user exists
    const user = await User.findOne({email})

    if(user) {
        res.status(422).json({errors: ["E-mail em uso. Por favor utilize outro e-mail."]})
    }

    // Generate password hash
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    // create User
    const newUser = await User.create({
        name,
        email,
        password: passwordHash
    })

    // if user was created succesfully, return the token
    if(!newUser){
        res.status(422).json({errors: ["Houve um erro, por fazer tente mais tarde"]});
        return
    }
    res.status(201).json({
        _id: newUser._id,
        token: generateToken(newUser._id),
    })
}

// Sign User in
const login = async (req, res) => {
    
    const { email, password } = req.body;


    try {
        const user = await User.findOne({email})

        // check if user exists
        if(!user){
            res.status(404).json({ errors: ['usuário não encontrado']})
            return
        }

        // check if the password matches.
        if(!(await bcrypt.compare(password, user.password))){
            res.status(422).json({errors: ["senha inválida"]})
        }
        
        res.status(200).json({
            _id: user._id,
            profileImage: user.profileImage,
            token: generateToken(user._id),
        });


    } catch (error) {
        console.log(error)
    }

    /* 
        Here I noticed that when I logged in with an wrong email or password, at firtst the validation would work. But if I tried again, the validation wouldn't run and user would get in without the right email or password.

        But after I used the try catch statement the validation would work perfectly. 

        With this in mind I think that the error of the user trying to log in with the wrong data made the backend application stop.
    */
}

// Get current logged in user
const getCurrentUser = async (req, res) => {
    const user = req.user

    res.status(200).json(user)
}

// Update a user
const update = async (req, res) => {
    const { name, password, bio } = req.body;

    let profileImage = null

    if(req.file){
        profileImage = req.file.filename;
    }

    const reqUser = req.user
    
    // const user = await User.findById(mongoose.Types.ObjectId(reqUser._id)).select("-password")

    const user = await User.findById(reqUser._id).select(
        "-password"
      );

    if(name){
        user.name = name
    }

    if(password) {
        // Generate password hash
        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);
        user.password = passwordHash
    }

    if(profileImage){
        user.profileImage = profileImage
    }

    if(bio){
        user.bio = bio
    }

    await user.save()

    res.status(200).json(user)
};

// get user by ID
const getUserById = async (req, res) =>{
    const {id} = req.params
    
    try {
        const user = await User.findById(id).select("-password");
        // check if user exists 
        if(!user){
            res.status(404).json({errors: ["Usuário não encontrado."]})
            return;
        }
        res.status(200).json(user)        
    } catch (error) {
        res.status(404).json({errors: ["Usuário não encontrado."]})
    }
}

module.exports = {
    register,
    login,
    getCurrentUser,
    update,
    getUserById
}
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import nodemailer from 'nodemailer';
import cron from 'node-cron';
import dotenv from 'dotenv';
import User from './models/user_model.js';
import Reminder from './models/reminder_model.js';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';


dotenv.config()
const app = express()
app.use(express.json())
app.use(cookieParser())
app.use(passport.initialize())


// Google Oauth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;

        let user = await User.findOne({ email });

        if (!user) {
          user = await User.create({
            name: profile.displayName,
            email: email,
            password: null // dummy password
          });
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

//On clicking this route the user will get the google login pop-up
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);


app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    const token = jwt.sign(
      { id: req.user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("token", token, { httpOnly: true });

    res.send("Google login successful. You can close this tab.");
  }
);


app.get('/', (req, res) => {
    res.send("I am working")
})


//Connect mongoDB 
async function start() {
    try {
        await mongoose.connect(process.env.MONGODB_URL)
        console.log('MongoDB connected');

        const PORT = 4000;
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
            
        })
        
    } catch (error) {
        console.log('MongoDB connection error:', error);
        
    }
}

//Create Transporter for sending mail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
})


//Auth middleware
const authMiddleware = async (req, res, next) => {
    const token = req.cookies.token
    if(!token){
        return res.status(401).json({ message: "Token not provided" })
    }
    const decodeToken = jwt.verify(token, process.env.JWT_SECRET)
    const user = await User.findOne({ email })

    if(!user){
        return res.status(401).json({ message: "Invalid token" })
    }

    req.user = user
    next()
}


// Routes

// Register
app.post('/register', async (req, res) => {

    const { name, email, password } = req.body
    if(!(name || email || password)){
        return res.status(401).json({ message: "All fields are required" })
    }

    const user = await User.findOne({ email })
    if(user){
        return res.status(401).json({ message: "User already exists" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    await User.create({
        email,
        name,
        password: hashedPassword
    })

    res.status(201).json({ message: "User registered" })
})

//Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body

    const user = await User.findOne({ email })
    if(!user){
        return res.status(400).json({ message: "User not found" })
    }

    if(!user.password){
        return res.status(400).json({ message: "Use google login for this account" })
    }

    const isPasswordValid = await bcrypt.compare(password, user.password)
    if(!isPasswordValid){
        return res.status(400).json({ message: "Wrong password" })
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET)
    res.cookie("token", token, {httpOnly: true})

    res.json({ message: "Login succesfull" })
})

// Logout
app.post('/logout', (req, res) => {
    res.clearCookie("token")
    res.json({ message: "Logged out" })
})


// REMINDER ROUTES

//Create reminder
app.post('/reminder', authMiddleware, async (req, res) => {
    const { title, message, sendAt } = req.body
    const reminder = await Reminder.create({
        userId: req.userId,
        title,
        message,
        sendAt: new Date(sendAt)
    })
    await reminder.save();
    res.status(201).json(reminder)
})

//Get my reminder
app.get('/reminder', authMiddleware, async(req, res) => {
    const reminders = await Reminder.find({ userId: req.userId })
    res.json(reminders)
})



//************************ Cron job ******************************
cron.schedule('* * * * *', async () => {
    const now = new Date();

    const dueReminders = await Reminder.find({ sent: false, sendAt: { $lte: now } }).populate('userId', 'email');

    for(const reminder of dueReminders){
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: reminder.userId.email,
            subject: reminder.title,
            text: reminder.message 
        })

        reminder.sent = true
        await reminder.save()
    }
})


start()
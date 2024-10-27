// server/server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken"); // JWT package

const bcrypt = require("bcrypt"); // For password hashing

const otpEmailTemplate = require("./Mailtemplates/otpEmailTemplate.js");
const userPasswordEmailTemplate = require("./Mailtemplates/userPasswordEmailTemplate.js");

const app = express();
const PORT = process.env.PORT || 5000;

// CORS Configuration to allow all origins
const corsOptions = {
    origin: "http://localhost:3000", // Your frontend URL
    credentials: true,
    allowedHeaders: ["Authorization", "Content-Type"],
    methods: ["GET", "POST", "PUT"], // Add PUT method
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));

// Nodemailer setup section start 👇

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    },
});

// Nodemailer setup section end 👆

// rgistraion notificion fincation section start 👇

const sendEmailNotification = async(role, email, name) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL, // Notification email
        subject: `${role} Registration Notification`,
        html: `<p>A new ${role} has registered:</p>
               <p>Name: ${name}</p>
               <p>Email: ${email}</p>`,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`${role} registration notification sent to xyz@gmail.com`);
    } catch (error) {
        console.error("Error sending registration notification email:", error);
    }
};

// rgistraion notificion fincation section start ☝️

// this is the default route section start 👇

app.get("/", (req, res) => {
    res.send("Hello from the server!");
});

// this is the default route section end 👆

// this is the User section start 👇

// User Schema
const userSchema = new mongoose.Schema({
    fullName: String,
    dob: String,
    city: String,
    state: String,
    phone: String,
    email: { type: String, unique: true },
    password: String,
    isLoginDisabled: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

// OTP Store (Temporary, could be replaced with a Redis database for scalability)
const otpStore = {};

// User Route: User Register
app.post("/user/register", async(req, res) => {
    const { fullName, dob, city, state, phone, email } = req.body;

    // Check if the email already exists in the database
    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.status(400).json({ message: "Email is already registered." });
    }

    // Generate a strong random password
    const password =
        Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8); // Simple strong password generation logic
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Save OTP to the otpStore for the email
    otpStore[email] = otp;

    // Send the OTP via email
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your OTP for Registration",
        html: otpEmailTemplate(otp, fullName),
    };

    try {
        await transporter.sendMail(mailOptions);

        // Save the user with the hashed password
        const newUser = new User({
            fullName,
            dob,
            city,
            state,
            phone,
            email,
            password: hashedPassword, // Store the hashed password
            isVerified: true, // Automatically set as verified for this case
        });
        await newUser.save();

        // Send email notification to xyz@gmail.com
        await sendEmailNotification('User', email, fullName);

        res.status(200).json({ message: "OTP sent to email" });
    } catch (error) {
        console.error("Error sending OTP email:", error);
        res.status(500).json({ message: "Error sending OTP" });
    }
});

// User Route: User OTP verify
app.post("/user/verify-otp", async(req, res) => {
    const { fullName, dob, city, state, phone, email, otp } = req.body;

    // Check if the OTP matches the one sent to the user's email
    if (otpStore[email] && otpStore[email] == otp) {
        // Remove OTP from store after verification
        delete otpStore[email];
        res.status(200).json({ message: "User registered successfully" });
    } else {
        res.status(400).json({ message: "Invalid OTP" });
    }
});

// User Route: User Login
app.post("/user/login", async(req, res) => {
    const { email } = req.body;

    // Check if the email is registered
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: "Email is not registered." });
    }

    if (user.isLoginDisabled) {
        return res.status(403).json({ message: "Login disabled by admin" });
    }

    // Generate a new random password
    const password =
        Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the new password
    user.password = hashedPassword; // Update user's password
    await user.save(); // Save the updated user

    // Send the new password via email
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your New Password",
        html: userPasswordEmailTemplate(password),
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "New password sent to email" });
    } catch (error) {
        console.error("Error sending new password email:", error);
        res.status(500).json({ message: "Error sending new password" });
    }
});

// User Route: Authenticate and generate JWT
app.post("/user/authenticate", async(req, res) => {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    // // Check if login is disabled
    // if (user.isLoginDisabled) {
    //     return res.status(403).json({ message: "Your account has been disabled." });
    // }

    // Verify the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    // Create JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

    // Set the token in a cookie
    res.cookie("UserToken", token, {
        httpOnly: false, // Prevent JavaScript access to the cookie
        secure: process.env.NODE_ENV === "production", // Use secure cookies in production
        sameSite: "Lax", // Adjust according to your needs
        path: "/", // Ensure the cookie is available on all routes
    });

    console.log(token);

    res.status(200).json({
        message: "Login successful",
        token,
    }); // No need to return the token here
});

// User Route: Get User Profile
app.get("/user/profile", async(req, res) => {
    const authHeader = req.headers.authorization; // Get the Authorization header

    if (!authHeader) {
        return res.status(401).json({ message: "No token provided." });
    }

    const token = authHeader.split(" ")[1]; // Extract the token from the Authorization header

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify the token
        const user = await User.findById(decoded.id).select(
            "-password -isVerified -__v -_id"
        ); // Fetch the user data without password

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        res.status(200).json(user); // Return user data
    } catch (err) {
        res.status(401).json({ message: "Invalid token." }); // Token verification failed
        console.log(err);
    }
});

// this is the User section end 👆

// this is the user study tracting section start 👇

// Study Tracking Schema

const studyTrackingSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: "User" },
    subject: { type: String, required: true },
    topic: { type: String, required: true },
    submissions: [{
        date: { type: String, required: true }, // Store submission date
        questionsAttempted: { type: Number, required: true },
        questionsSolvedCorrectly: { type: Number, required: true },
        submissionStatus: { type: Boolean, default: false },
    }, ],
});

// Create a unique index on userId and topic
studyTrackingSchema.index({ userId: 1, topic: 1, submittedOn: 1 }, { unique: true });

const StudyTracking = mongoose.model("StudyTracking", studyTrackingSchema);

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extract the token from the header

    console.log("Authorization Header:", authHeader); // Log the auth header
    console.log("Token:", token); // Log the token

    if (!token) {
        console.error("No token provided");
        return res.sendStatus(401); // If no token, return unauthorized
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token verification failed:", err);
            return res.sendStatus(403); // If token is invalid, return forbidden
        }
        req.userId = user.id; // Attach userId to the request object
        next(); // Proceed to the next middleware or route handler
    });
};

// New endpoint to check submission status for a specific date and topic
app.get("/check-submission", authenticateToken, async(req, res) => {
    const { date, topic } = req.query; // Get the date and topic from query params
    const userId = req.userId; // Get userId from the authenticated token

    const submission = await StudyTracking.findOne({
        userId,
        topic,
        "submissions.date": date, // Check in the submissions array
    });

    if (submission) {
        return res.status(200).json({ submitted: true });
    }
    return res.status(200).json({ submitted: false });
});

// Updated Track study route
app.post("/track-study", authenticateToken, async(req, res) => {
    const { userId } = req; // Get userId from the authenticated token
    const { subject, topic, questionsAttempted, questionsSolvedCorrectly } =
    req.body;

    const today = new Date().toLocaleDateString("en-GB"); // Format the date as DD-MM-YYYY

    try {
        // Check if an entry for this user and topic already exists
        const studyEntry = await StudyTracking.findOne({ userId, topic });

        if (!studyEntry) {
            // If no entry exists, create a new one
            const newStudyEntry = new StudyTracking({
                userId,
                subject,
                topic,
                submissions: [{
                    date: today,
                    questionsAttempted,
                    questionsSolvedCorrectly,
                    submissionStatus: true,
                }, ],
            });
            await newStudyEntry.save(); // Save the new study tracking entry
            return res
                .status(201)
                .json({ message: "Study tracking entry created successfully." });
        } else {
            // If an entry exists, check if the user already submitted today
            const existingSubmission = studyEntry.submissions.find(
                (submission) => submission.date === today
            );

            if (existingSubmission) {
                return res.status(400).json({
                    message: "You have already submitted today for this topic.",
                });
            } else {
                // If no submission exists for today, add a new submission
                studyEntry.submissions.push({
                    date: today,
                    questionsAttempted,
                    questionsSolvedCorrectly,
                    submissionStatus: true,
                });
                await studyEntry.save(); // Save the updated study tracking entry
                return res
                    .status(201)
                    .json({ message: "Study tracking entry updated successfully." });
            }
        }
    } catch (error) {
        console.error("Error saving study tracking data:", error);
        res.status(500).json({ message: "Error saving data. Please try again." });
    }
});

// Endpoint to fetch all submissions for a specific topic and user
app.get("/get-submissions", authenticateToken, async(req, res) => {
    const { topic } = req.query; // Get the topic from query params
    const userId = req.userId; // Get userId from the authenticated token

    try {
        const studyEntry = await StudyTracking.findOne({ userId, topic });

        if (studyEntry) {
            return res.status(200).json(studyEntry.submissions); // Return all submissions for the topic
        } else {
            return res
                .status(404)
                .json({ message: "No submissions found for this topic." });
        }
    } catch (error) {
        console.error("Error fetching study submissions:", error);
        return res.status(500).json({ message: "Error fetching submissions." });
    }
});

// this is the user study tracting section end 👆

// this is the admin moudule section start 👇

// Admin Schema
const adminSchema = new mongoose.Schema({
    fullName: String,
    phone: String,
    email: { type: String, unique: true },
    password: String,
    isVerified: { type: Boolean, default: false },
});

const Admin = mongoose.model("Admin", adminSchema);

// OTP Store (Temporary, could be replaced with Redis)
const adminOtpStore = {};

// Admin Route: Admin Register
app.post("/admin/register", async(req, res) => {
    const { fullName, phone, email } = req.body;

    // Check if the email already exists
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
        return res.status(400).json({ message: "Email is already registered." });
    }

    // Generate OTP and store it
    const otp = Math.floor(100000 + Math.random() * 900000);
    adminOtpStore[email] = otp;

    // Send the OTP via email
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Admin Registration OTP",
        html: otpEmailTemplate(otp, fullName),
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "OTP sent to email." });
    } catch (error) {
        res.status(500).json({ message: "Error sending OTP" });
    }
});

// Admin Route: Admin OTP verify
app.post("/admin/verify-otp", async(req, res) => {
    const { fullName, phone, email, otp } = req.body;

    // Verify OTP
    if (adminOtpStore[email] && adminOtpStore[email] == otp) {
        // Create a strong password for the admin
        const password = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the admin
        const newAdmin = new Admin({
            fullName,
            phone,
            email,
            password: hashedPassword,
            isVerified: true,
        });
        await newAdmin.save();

        // Send email notification to xyz@gmail.com
        await sendEmailNotification('User', email, fullName);

        delete adminOtpStore[email]; // Remove OTP after successful verification
        res.status(200).json({ message: "Admin registered successfully." });
    } else {
        res.status(400).json({ message: "Invalid OTP." });
    }
});

// Admin Login
app.post("/admin/login", async(req, res) => {
    const { email } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) {
        return res.status(400).json({ message: "Email is not registered." });
    }

    const password = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(password, 10);
    admin.password = hashedPassword;
    await admin.save();

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your New Password",
        html: userPasswordEmailTemplate(password),
    };

    try {
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "New password sent to email" });
    } catch (error) {
        console.error("Error sending new password email:", error);
        res.status(500).json({ message: "Error sending new password" });
    }
});

// Admin Authenticate and generate JWT
app.post("/admin/authenticate", async(req, res) => {
    const { email, password } = req.body;

    const admin = await Admin.findOne({ email });
    if (!admin) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
        return res.status(400).json({ message: "Invalid email or password." });
    }

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET);
    res.cookie("AdminToken", token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === "production",
        sameSite: "Lax",
        path: "/",
    });

    res.status(200).json({
        message: "Admin login successful",
        token,
    });
});

// Admin Route: Get Admin Profile
app.get("/admin/profile", authenticateToken, async(req, res) => {
    try {
        const admin = await Admin.findById(req.userId).select("-password");
        if (!admin) {
            return res.status(404).json({ message: "Admin not found." });
        }
        res.status(200).json(admin);
    } catch (error) {
        console.error("Error fetching admin profile:", error);
        res.status(500).json({ message: "Error fetching admin profile." });
    }
});

// Admin Route: Get User Count
app.get("/admin/user-count", authenticateToken, async(req, res) => {
    try {
        const count = await User.countDocuments(); // Count registered users
        res.status(200).json({ count });
    } catch (error) {
        console.error("Error fetching user count:", error);
        res.status(500).json({ message: "Error fetching user count." });
    }
});

// User Route: Get all users
app.get("/admin/users", authenticateToken, async(req, res) => {
    try {
        const users = await User.find().select("-password -isVerified -__v "); // Exclude sensitive fields
        res.status(200).json(users);
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({ message: "Error fetching users." });
    }
});

// User Route: Get user details by ID
app.get("/admin/users/:id", authenticateToken, async(req, res) => {
    try {
        const user = await User.findById(req.params.id).select(
            "-password -isVerified -__v "
        ); // Exclude sensitive fields
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error("Error fetching user details:", error);
        res.status(500).json({ message: "Error fetching user details." });
    }
});

// Admin Route: Toggle User Login Status
app.put("/admin/toggle-login-status/:userId", async(req, res) => {
    const { userId } = req.params;
    const { isLoginDisabled } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        user.isLoginDisabled = isLoginDisabled;
        await user.save();

        res.json({ message: "User login status updated successfully" });
    } catch (error) {
        res.status(500).json({ message: "Error updating user login status" });
    }
});

// Admin Route: Get User Submission Stats by Subject
app.get("/admin/user-stats", authenticateToken, async(req, res) => {
    const { userId } = req.query; // Get the userId from query params
    console.log({ userId }); // Check if userId is being logged

    if (!userId) {
        return res.status(400).json({ message: "User ID is required." });
    }

    try {
        const stats = await StudyTracking.find({ userId });
        console.log(stats); // Log the stats retrieved

        // Group and sum statistics by subject
        const groupedStats = stats.reduce((acc, entry) => {
            const { subject, submissions } = entry;

            // Initialize subject if it doesn't exist
            if (!acc[subject]) {
                acc[subject] = {
                    subject,
                    totalQuestionsAttempted: 0,
                    totalQuestionsSolvedCorrectly: 0,
                };
            }

            // Sum up questions attempted and solved correctly
            submissions.forEach((submission) => {
                acc[subject].totalQuestionsAttempted += submission.questionsAttempted;
                acc[subject].totalQuestionsSolvedCorrectly +=
                    submission.questionsSolvedCorrectly;
            });

            return acc;
        }, {});

        // Convert the grouped stats object to an array
        const formattedStats = Object.values(groupedStats);

        res.status(200).json(formattedStats); // Return formatted statistics grouped by subject
    } catch (error) {
        console.error("Error fetching user statistics:", error);
        return res.status(500).json({ message: "Error fetching statistics." });
    }
});

// this is the admin moudule section end ☝️

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
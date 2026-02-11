require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ================= DATABASE =================

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.log("❌ MongoDB Error:", err));

// ================= MODELS =================

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const projectSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    title: { type: String, required: true },
    description: { type: String },
}, { timestamps: true });

const Project = mongoose.model("Project", projectSchema);

// ================= AUTH MIDDLEWARE =================

function auth(req, res, next) {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "Access Denied" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch {
        res.status(400).json({ message: "Invalid Token" });
    }
}

// ================= ROUTES =================

// Home
app.get("/", (req, res) => {
    res.send("🚀 Backend Running Successfully");
});

// Register
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const userExists = await User.findOne({ email });
        if (userExists) return res.status(400).json({ message: "User already exists" });

        const hashed = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashed
        });

        await user.save();
        res.json({ message: "User registered successfully" });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "User not found" });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ message: "Incorrect password" });

        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({ token });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create Project
app.post("/api/projects", auth, async (req, res) => {
    try {
        const { title, description } = req.body;

        const project = new Project({
            userId: req.user.id,
            title,
            description
        });

        await project.save();
        res.json(project);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get All Projects
app.get("/api/projects", auth, async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.user.id });
        res.json(projects);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete Project
app.delete("/api/projects/:id", auth, async (req, res) => {
    try {
        await Project.findOneAndDelete({
            _id: req.params.id,
            userId: req.user.id
        });

        res.json({ message: "Project deleted" });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ================= SERVER =================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`🔥 Server running on port ${PORT}`);
});

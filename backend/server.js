require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);

// Basic Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Connection Error:', err));

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'freelance-platform',
    allowed_formats: ['jpg', 'jpeg', 'png', 'pdf']
  }
});
const upload = multer({ storage });

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['client', 'freelancer'], required: true },
  profile: {
    name: String,
    avatar: String,
    skills: [String],
    hourlyRate: Number,
    bio: String,
    experience: Number,
    completedProjects: { type: Number, default: 0 },
    totalEarnings:     { type: Number, default: 0 },
    rating:            { type: Number, default: 0 },
    reviews: [{
      reviewer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
      rating: Number,
      comment: String,
      date: { type: Date, default: Date.now }
    }]
  },
  isOnline: { type: Boolean, default: false },
  lastSeen: Date,
  notifications: [{
    type: { type: String },
    message: { type: String },
    read: { type: Boolean, default: false },
    date: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
  title:       { type: String, required: true },
  description: { type: String, required: true },
  budget:      { type: Number, required: true },
  skills:      [String],
  client:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  freelancer:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: {
    type: String,
    enum: ['open', 'in-progress', 'completed', 'cancelled'],
    default: 'open'
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'pending'
  },
  paymentId: String,
  deadline: Date,
  attachments: [{
    name: String,
    url: String,
    type: String
  }],
  driveLink: String,
  proposalCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const ProposalSchema = new mongoose.Schema({
  project:           { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  freelancer:        { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  coverLetter:       { type: String, required: true },
  bidAmount:         { type: Number, required: true },
  estimatedDuration: Number,
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending'
  },
  createdAt: { type: Date, default: Date.now }
});

const ChatSchema = new mongoose.Schema({
  participants: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    unreadCount: { type: Number, default: 0 },
    lastRead: Date
  }],
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  messages: [{
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    type: { type: String, enum: ['text', 'file', 'system'], default: 'text' },
    status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
    timestamp: { type: Date, default: Date.now }
  }],
  lastMessage: {
    content: String,
    timestamp: Date
  }
});

const TransactionSchema = new mongoose.Schema({
  project:      { type: mongoose.Schema.Types.ObjectId, ref: 'Project' },
  client:       { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  freelancer:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  amount:       { type: Number, required: true },
  stripePaymentIntentId: String,
  status: {
    type: String,
    enum: ['pending', 'completed', 'failed', 'refunded'],
    default: 'pending'
  },
  completedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

 const User = mongoose.model('User', UserSchema);
 const Project = mongoose.model('Project', ProjectSchema);
 const Proposal = mongoose.model('Proposal', ProposalSchema);
 const Chat = mongoose.model('Chat', ChatSchema);
 const Transaction = mongoose.model('Transaction', TransactionSchema);

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    console.log('Authenticated user:', user?.username);
    if (!user) throw new Error('User not found');
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Authentication failed' });
  }
};

const checkRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Access denied' });
  }
  next();
};

const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) throw new Error('Authentication error');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error('User not found');
    socket.user = user;
    console.log(`Socket authenticated for user: ${user.username}`);
    next();
  } catch (err) {
    console.error('Socket auth error:', err.message);
    next(new Error('Authentication error'));
  }
});

let onlineUsers = new Map();

const connectedUsers = new Map(); // Use this instead of onlineUsers

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) throw new Error('Authentication error');
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) throw new Error('User not found');

    // Check if user already has an active connection
    const existingSocket = connectedUsers.get(user._id.toString());
    if (existingSocket) {
      // Disconnect the existing socket
      existingSocket.disconnect(true);
      connectedUsers.delete(user._id.toString());
    }

    socket.user = user;
    console.log(`Socket authenticated for user: ${user.username}`);
    next();
  } catch (err) {
    console.error('Socket auth error:', err.message);
    next(new Error('Authentication error'));
  }
});

io.on('connection', async (socket) => {
  const userId = socket.user._id.toString();
  
  // Store the new socket connection
  connectedUsers.set(userId, socket);
  
  // Update user status
  await User.findByIdAndUpdate(userId, { 
    isOnline: true, 
    lastSeen: new Date() 
  });

  console.log(`User ${socket.user.username} connected. Total connected users: ${connectedUsers.size}`);

  socket.on('join_chat', async (chatId) => {
    // Leave any previous chat rooms
    Array.from(socket.rooms).forEach(room => {
      if (room.startsWith('chat_')) {
        socket.leave(room);
      }
    });
    const roomName = `chat_${chatId}`;
    socket.join(roomName);
    console.log(`User ${socket.user.username} joined chat room: ${roomName}`);
    try {
      await Chat.findOneAndUpdate(
        { _id: chatId, 'participants.user': socket.user._id },
        {
          $set: {
            'participants.$.lastRead': new Date(),
            'participants.$.unreadCount': 0
          }
        }
      );
    } catch (error) {
      console.error('Error updating chat:', error);
    }
    // Broadcast a system event to others in this room
    socket.to(roomName).emit('user_joined', {
      chatId,
      userId: socket.user._id,
      username: socket.user.username
    });
  });

  socket.on('send_message', async (data, callback) => {
    try {
      const { chatId, content, recipientId } = data;
      if (!content?.trim()) {
        throw new Error('Message content cannot be empty');
      }

      const chat = await Chat.findById(chatId).populate('participants.user', 'username');
      if (!chat) {
        throw new Error('Chat not found');
      }

      const newMessage = {
        sender: userId,
        content: content.trim(),
        timestamp: new Date(),
        status: 'sent'
      };

      chat.messages.push(newMessage);
      chat.lastMessage = {
        content: content.trim(),
        timestamp: new Date()
      };

      // Update recipient's unread count
      const recipientParticipant = chat.participants.find(
        p => p.user._id.toString() === recipientId
      );
      if (recipientParticipant) {
        recipientParticipant.unreadCount += 1;
      }

      await chat.save();

      const messageToSend = {
        chatId,
        message: {
          ...newMessage,
          sender: {
            _id: userId,
            username: socket.user.username
          }
        }
      };

      // Emit to all users in the chat room
      io.to(`chat_${chatId}`).emit('new_message', messageToSend);

      // Send acknowledgment back to sender
      callback({ success: true });

    } catch (error) {
      console.error('Error sending message:', error);
      callback({ error: error.message });
    }
  });

  socket.on('disconnect', async () => {
    // Remove socket from connected users
    connectedUsers.delete(userId);
    
    // Update user status
    await User.findByIdAndUpdate(userId, { 
      isOnline: false, 
      lastSeen: new Date() 
    });

    console.log(`User ${socket.user.username} disconnected. Remaining users: ${connectedUsers.size}`);
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword, role });
    await user.save();
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({
      user: { _id: user._id, username: user.username, email: user.email, role: user.role },
      token
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({
      user: { _id: user._id, username: user.username, email: user.email, role: user.role },
      token
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/projects', auth, checkRole(['client']), upload.any(),  async (req, res) => {
  try {
    const { title, description, budget, skills, deadline, driveLink } = req.body;
    const project = new Project({
      title,
      description,
      budget,
      skills,
      deadline,
      driveLink,
      client: req.user._id
    });
    await project.save();
    // Notify matching freelancers
    const matchingFreelancers = await User.find({
      role: 'freelancer',
      'profile.skills': { $in: skills }
    });
    for (const freelancer of matchingFreelancers) {
      freelancer.notifications.push({
        type: 'new_project',
        message: `New project matching your skills: ${title}`
      });
      await freelancer.save();
    }
    res.status(201).json(project);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/projects', async (req, res) => {
  try {
    const { status, skills, minBudget, maxBudget, search, page = 1, limit = 10 } = req.query;
    let query = {};
    if (status) query.status = status;
    if (skills) query.skills = { $in: skills.split(',') };
    if (minBudget || maxBudget) {
      query.budget = {};
      if (minBudget) query.budget.$gte = Number(minBudget);
      if (maxBudget) query.budget.$lte = Number(maxBudget);
    }
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    const projects = await Project.find(query)
      .populate('client', 'username profile')
      .populate('freelancer', 'username profile')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit));
    const total = await Project.countDocuments(query);
    res.json({ projects, totalPages: Math.ceil(total / limit), currentPage: page });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/projects/:id', async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate('client', 'username profile')
      .populate('freelancer', 'username profile');
    if (!project) return res.status(404).json({ message: 'Project not found' });
    res.json(project);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/proposals', auth, checkRole(['freelancer']), async (req, res) => {
  try {
    const { projectId, coverLetter, bidAmount, estimatedDuration } = req.body;
    const project = await Project.findById(projectId);
    console.log('Project in proposal route:', project);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    if (project.status !== 'open') return res.status(400).json({ message: 'Project is no longer accepting proposals' });
    const existingProposal = await Proposal.findOne({ project: projectId, freelancer: req.user._id });
    if (existingProposal) return res.status(400).json({ message: 'You have already submitted a proposal for this project' });
    const proposal = new Proposal({
      project: projectId,
      freelancer: req.user._id,
      coverLetter,
      bidAmount,
      estimatedDuration
    });
    await proposal.save();
    project.proposalCount += 1;
    await project.save();
    const client = await User.findById(project.client);
    client.notifications.push({
      type: 'new_proposal',
      message: `New proposal received for project: ${project.title}`
    });
    await client.save();
    res.status(201).json(proposal);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/projects/:projectId/proposals', auth, async (req, res) => {
  try {
    const { projectId } = req.params;
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    if (project.client.toString() !== req.user._id.toString() && req.user.role !== 'freelancer') {
      return res.status(403).json({ message: 'Not authorized to view proposals' });
    }
    let proposals;
    if (req.user.role === 'freelancer') {
      proposals = await Proposal.find({ project: projectId, freelancer: req.user._id })
        .populate('freelancer', 'username profile');
    } else {
      proposals = await Proposal.find({ project: projectId })
        .populate('freelancer', 'username profile');
    }
    res.json(proposals);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.patch('/api/proposals/:proposalId', auth, checkRole(['client']), async (req, res) => {
  try {
    const { proposalId } = req.params;
    const { status } = req.body;
    const proposal = await Proposal.findById(proposalId)
      .populate('project')
      .populate('freelancer');
    if (!proposal) return res.status(404).json({ message: 'Proposal not found' });
    if (proposal.project.client.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized to update this proposal' });
    }
    proposal.status = status;
    await proposal.save();
    if (status === 'accepted') {
      // Update project status and assign freelancer
      await Project.findByIdAndUpdate(proposal.project._id, {
        status: 'in-progress',
        freelancer: proposal.freelancer._id
      });
      // Reject all other proposals for this project
      await Proposal.updateMany(
        { project: proposal.project._id, _id: { $ne: proposalId } },
        { status: 'rejected' }
      );
      // Notify the freelancer
      proposal.freelancer.notifications.push({
        type: 'proposal_accepted',
        message: `Your proposal for project "${proposal.project.title}" has been accepted!`
      });
      await proposal.freelancer.save();

      let chat = await Chat.findOne({
        participants: { $all: [ { user: proposal.project.client }, { user: proposal.freelancer._id } ] },
        project: proposal.project._id
      });
      if (!chat) {
        chat = new Chat({
          participants: [
            { user: proposal.project.client },
            { user: proposal.freelancer._id }
          ],
          project: proposal.project._id,
          messages: []
        });
        await chat.save();
      }
    }
    res.json(proposal);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


app.delete('/api/proposals/:proposalId', auth, checkRole(['freelancer']), async (req, res) => {
  try {
    const proposal = await Proposal.findById(req.params.proposalId);
    if (!proposal) return res.status(404).json({ message: 'Proposal not found' });
    if (proposal.freelancer.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized to delete this proposal' });
    }
    if (proposal.status !== 'pending') return res.status(400).json({ message: 'Cannot delete non-pending proposals' });
    await proposal.remove();
    await Project.findByIdAndUpdate(proposal.project, { $inc: { proposalCount: -1 } });
    res.json({ message: 'Proposal deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// POST /api/chats — create or return an existing chat
app.post('/api/chats', auth, async (req, res) => {
  try {
    const { recipientId, projectId } = req.body;
    let chat = await Chat.findOne({
      participants: { $all: [ { user: req.user._id }, { user: recipientId } ] },
      project: projectId
    });
    if (!chat) {
      chat = new Chat({
        participants: [
          { user: req.user._id },
          { user: recipientId }
        ],
        project: projectId,
        messages: []
      });
      await chat.save();
    }
    await chat.populate('participants.user', 'username profile.avatar isOnline lastSeen');
    await chat.populate('project', 'title');
    res.json(chat);
  } catch (error) {
    console.error('POST /api/chats error:', error);
    res.status(500).json({ message: error.message });
  }
});

// GET /api/chats — list all chats for the current user
app.get('/api/chats', auth, async (req, res) => {
  try {
    const chats = await Chat.find({ 'participants.user': req.user._id })
      .populate('participants.user', 'username profile.avatar isOnline lastSeen')
      .populate('project', 'title')
      .sort({ 'lastMessage.timestamp': -1 });
    res.json(chats);
  } catch (error) {
    console.error('GET /api/chats error:', error);
    res.status(500).json({ message: error.message });
  }
});


app.post('/api/payments/create-intent', auth, checkRole(['client']), async (req, res) => {
  try {
    const { projectId } = req.body;
    const project = await Project.findById(projectId).populate('freelancer');
    if (!project) return res.status(404).json({ message: 'Project not found' });
    if (project.client.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: 'Not authorized' });
    }
    const paymentIntent = await stripe.paymentIntents.create({
      amount: project.budget * 100,
      currency: 'usd',
      metadata: {
        projectId: project._id.toString(),
        clientId: req.user._id.toString(),
        freelancerId: project.freelancer._id.toString()
      }
    });
    const transaction = new Transaction({
      project: project._id,
      client: req.user._id,
      freelancer: project.freelancer._id,
      amount: project.budget,
      stripePaymentIntentId: paymentIntent.id
    });
    await transaction.save();
    project.paymentStatus = 'processing';
    await project.save();
    console.log('Payment intent created for project:', project._id);
    res.json({ clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/payments/confirm', auth, async (req, res) => {
  try {
    const { paymentIntentId, projectId } = req.body;
    if (!paymentIntentId || !projectId) {
      return res.status(400).json({ message: 'Payment intent ID and project ID are required' });
    }
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    const existingTransaction = await Transaction.findOne({
      stripePaymentIntentId: paymentIntentId,
      status: 'completed'
    });
    if (existingTransaction) {
      return res.status(400).json({ message: 'Payment already processed' });
    }
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
    if (paymentIntent.status !== 'succeeded') throw new Error('Payment not successful');

    const session = await mongoose.startSession();
    session.startTransaction();
    try {
      const transaction = await Transaction.findOneAndUpdate(
        { stripePaymentIntentId: paymentIntentId },
        { status: 'completed', completedAt: new Date() },
        { new: true, session }
      );
      await Project.findByIdAndUpdate(
        projectId,
        { status: 'completed', paymentStatus: 'completed' },
        { new: true, session }
      );
      await User.findByIdAndUpdate(
        project.freelancer,
        { $inc: { 'profile.completedProjects': 1, 'profile.totalEarnings': project.budget } },
        { session }
      );
      await session.commitTransaction();
      res.json({ success: true, transaction });
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    res.json({ url: req.file.path, filename: req.file.filename });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/reviews', auth, async (req, res) => {
  try {
    const { projectId, freelancerId, rating, comment } = req.body;
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    if (project.status !== 'completed') return res.status(400).json({ message: 'Can only review completed projects' });
    const freelancer = await User.findById(freelancerId);
    freelancer.profile.reviews.push({ reviewer: req.user._id, projectId, rating, comment });
    const totalRating = freelancer.profile.reviews.reduce((sum, review) => sum + review.rating, 0);
    freelancer.profile.rating = totalRating / freelancer.profile.reviews.length;
    await freelancer.save();
    res.json(freelancer);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/profile', auth, async (req, res) => {
  try {
    res.json(req.user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/profile', auth, async (req, res) => {
  try {
    const { name, bio, skills, hourlyRate } = req.body;
    req.user.profile.name = name;
    req.user.profile.bio = bio;
    req.user.profile.skills = skills;
    if (hourlyRate !== undefined) req.user.profile.hourlyRate = hourlyRate;
    await req.user.save();
    res.json(req.user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.patch('/api/projects/:id/status', auth, async (req, res) => {
  try {
    const { status } = req.body;
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json({ message: 'Project not found' });
    const validTransitions = {
      'open': ['in-progress', 'cancelled'],
      'in-progress': ['completed', 'cancelled'],
      'completed': [],
      'cancelled': []
    };
    if (!validTransitions[project.status].includes(status)) {
      return res.status(400).json({ message: `Invalid status transition from ${project.status} to ${status}` });
    }
    project.status = status;
    await project.save();
    res.json(project);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
// module.exports = { User, Project, Proposal, Chat, Transaction };

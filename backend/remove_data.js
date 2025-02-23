// resetData.js
require('dotenv').config();
const mongoose = require('mongoose');

const { User, Project, Proposal, Chat, Transaction } =  require("./server");

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(async () => {
  console.log('Connected to MongoDB');

  // Delete all documents from the collections
  await Promise.all([
    User.deleteMany({}),
    Project.deleteMany({}),
    Proposal.deleteMany({}),
    Chat.deleteMany({}),
    Transaction.deleteMany({})
  ]);

  console.log('All data has been reset successfully.');
  process.exit(0);
})
.catch(err => {
  console.error('Error connecting to MongoDB:', err);
  process.exit(1);
});

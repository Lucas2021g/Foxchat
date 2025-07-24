// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors'); // Import cors
const cloudinary = require('cloudinary').v2;
const { Buffer } = require('buffer'); // Import Buffer

// Models
const User = require('./models/User');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

// Use CORS middleware
const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:8080'; // Default for local dev
app.use(cors({
    origin: frontendUrl,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));


const io = socketIo(server, {
    cors: {
        origin: frontendUrl,
        methods: ["GET", "POST"],
        credentials: true
    },
    // Add pingInterval and pingTimeout for better connection stability
    pingInterval: 25000, // Send a ping every 25 seconds
    pingTimeout: 60000   // Disconnect if no pong received for 60 seconds
});

// Middleware
app.use(express.json()); // For parsing application/json

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Encryption keys from environment variables
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes for AES-256
const IMAGE_ENCRYPTION_KEY = Buffer.from(process.env.IMAGE_ENCRYPTION_KEY, 'hex'); // 32 bytes for image encryption

if (ENCRYPTION_KEY.length !== 32 || IMAGE_ENCRYPTION_KEY.length !== 32) {
    console.error('Encryption keys must be 32 bytes (64 hex characters) long.');
    process.exit(1);
}

// Function to encrypt text (for messages)
function encryptText(text) {
    const iv = crypto.randomBytes(16); // Initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}

// Function to decrypt text (for messages)
function decryptText(encryptedData, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Function to encrypt image buffer
function encryptImage(buffer) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', IMAGE_ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('base64') };
}

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- Database Connection ---
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));


// --- Routes ---

// Register
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        if (err.code === 11000) { // Duplicate key error
            return res.status(409).json({ message: 'Username or email already exists' });
        }
        res.status(500).json({ message: 'Error registering user', error: err.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, username: user.username, userId: user._id });
    } catch (err) {
        res.status(500).json({ message: 'Error logging in', error: err.message });
    }
});

// Get user info (for friend search or self info)
app.get('/user/:username', authenticateToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username }).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching user', error: err.message });
    }
});

// Get user's friend list and pending requests
app.get('/friends', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .populate('friends', 'username') // Only populate username
            .populate('sentRequests', 'username')
            .populate('receivedRequests', 'username')
            .select('friends sentRequests receivedRequests');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({
            friends: user.friends,
            sentRequests: user.sentRequests,
            receivedRequests: user.receivedRequests
        });
    } catch (err) {
        console.error('Error fetching friends and requests:', err);
        res.status(500).json({ message: 'Error fetching friends and requests', error: err.message });
    }
});


// Send friend request
app.post('/friend-request/:recipientUsername', authenticateToken, async (req, res) => {
    try {
        const sender = await User.findById(req.user.id);
        const recipient = await User.findOne({ username: req.params.recipientUsername });

        if (!sender || !recipient) {
            return res.status(404).json({ message: 'Sender or recipient not found' });
        }

        if (sender._id.equals(recipient._id)) {
            return res.status(400).json({ message: 'Cannot send friend request to yourself' });
        }

        // Check if already friends
        if (sender.friends.includes(recipient._id)) {
            return res.status(400).json({ message: 'Already friends' });
        }

        // Check if request already sent or received
        if (sender.sentRequests.includes(recipient._id) || sender.receivedRequests.includes(recipient._id)) {
            return res.status(400).json({ message: 'Friend request already pending' });
        }

        // Check if recipient has sent a request to sender (mutual request)
        if (recipient.sentRequests.includes(sender._id)) {
            // Auto-accept if mutual
            sender.friends.push(recipient._id);
            recipient.friends.push(sender._id);

            recipient.sentRequests = recipient.sentRequests.filter(id => !id.equals(sender._id)); // Remove from recipient's sent
            sender.receivedRequests = sender.receivedRequests.filter(id => !id.equals(recipient._id)); // Remove from sender's received

            await sender.save();
            await recipient.save();

            // Notify both users of new friendship
            io.to(sender._id.toString()).emit('friend_accepted', { username: recipient.username, userId: recipient._id });
            io.to(recipient._id.toString()).emit('friend_accepted', { username: sender.username, userId: sender._id });
            return res.status(200).json({ message: 'Friend request accepted automatically' });
        }


        sender.sentRequests.push(recipient._id);
        recipient.receivedRequests.push(sender._id);

        await sender.save();
        await recipient.save();

        // Notify recipient of new request
        io.to(recipient._id.toString()).emit('friend_request', { username: sender.username, userId: sender._id });
        res.status(200).json({ message: 'Friend request sent' });

    } catch (err) {
        console.error('Error sending friend request:', err);
        res.status(500).json({ message: 'Error sending friend request', error: err.message });
    }
});

// Accept friend request
app.post('/friend-request/:senderUsername/accept', authenticateToken, async (req, res) => {
    try {
        const recipient = await User.findById(req.user.id);
        const sender = await User.findOne({ username: req.params.senderUsername });

        if (!recipient || !sender) {
            return res.status(404).json({ message: 'Recipient or sender not found' });
        }

        if (!recipient.receivedRequests.includes(sender._id)) {
            return res.status(400).json({ message: 'No pending request from this user' });
        }

        // Remove from pending lists
        recipient.receivedRequests = recipient.receivedRequests.filter(id => !id.equals(sender._id));
        sender.sentRequests = sender.sentRequests.filter(id => !id.equals(recipient._id));

        // Add to friends lists
        recipient.friends.push(sender._id);
        sender.friends.push(recipient._id);

        await recipient.save();
        await sender.save();

        // Notify both users of new friendship
        io.to(recipient._id.toString()).emit('friend_accepted', { username: sender.username, userId: sender._id });
        io.to(sender._id.toString()).emit('friend_accepted', { username: recipient.username, userId: recipient._id });
        res.status(200).json({ message: 'Friend request accepted' });
    } catch (err) {
        console.error('Error accepting friend request:', err);
        res.status(500).json({ message: 'Error accepting friend request', error: err.message });
    }
});

// Decline or Cancel friend request
app.post('/friend-request/:targetUsername/decline-cancel', authenticateToken, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user.id);
        const targetUser = await User.findOne({ username: req.params.targetUsername });

        if (!currentUser || !targetUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        let message = 'No pending request to decline/cancel from/to this user.';

        // Check if current user sent the request (cancel)
        if (currentUser.sentRequests.includes(targetUser._id)) {
            currentUser.sentRequests = currentUser.sentRequests.filter(id => !id.equals(targetUser._id));
            targetUser.receivedRequests = targetUser.receivedRequests.filter(id => !id.equals(currentUser._id));
            message = 'Friend request cancelled.';
            // Notify target user that request was cancelled
            io.to(targetUser._id.toString()).emit('friend_request_cancelled', { username: currentUser.username, userId: currentUser._id });
        }
        // Check if current user received the request (decline)
        else if (currentUser.receivedRequests.includes(targetUser._id)) {
            currentUser.receivedRequests = currentUser.receivedRequests.filter(id => !id.equals(targetUser._id));
            targetUser.sentRequests = targetUser.sentRequests.filter(id => !id.equals(currentUser._id));
            message = 'Friend request declined.';
            // Notify target user that request was declined
            io.to(targetUser._id.toString()).emit('friend_request_declined', { username: currentUser.username, userId: currentUser._id });
        } else {
            return res.status(400).json({ message });
        }

        await currentUser.save();
        await targetUser.save();

        res.status(200).json({ message });

    } catch (err) {
        console.error('Error declining/cancelling friend request:', err);
        res.status(500).json({ message: 'Error processing friend request', error: err.message });
    }
});

// Remove friend
app.post('/friend/:friendUsername/remove', authenticateToken, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user.id);
        const friendUser = await User.findOne({ username: req.params.friendUsername });

        if (!currentUser || !friendUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!currentUser.friends.includes(friendUser._id)) {
            return res.status(400).json({ message: 'Not friends with this user' });
        }

        // Remove from current user's friends list
        currentUser.friends = currentUser.friends.filter(id => !id.equals(friendUser._id));
        // Remove from friend's friends list
        friendUser.friends = friendUser.friends.filter(id => !id.equals(currentUser._id));

        await currentUser.save();
        await friendUser.save();

        // Notify both users of friend removal
        io.to(currentUser._id.toString()).emit('friend_removed', { username: friendUser.username, userId: friendUser._id });
        io.to(friendUser._id.toString()).emit('friend_removed', { username: currentUser.username, userId: currentUser._id });

        res.status(200).json({ message: 'Friend removed successfully' });

    } catch (err) {
        console.error('Error removing friend:', err);
        res.status(500).json({ message: 'Error removing friend', error: err.message });
    }
});


// Get chat history between two users
app.get('/messages/:friendId', authenticateToken, async (req, res) => {
    try {
        const currentUserId = req.user.id;
        const friendId = req.params.friendId;

        const messages = await Message.find({
            $or: [
                { sender: currentUserId, recipient: friendId },
                { sender: friendId, recipient: currentUserId }
            ]
        }).sort('timestamp');

        // Decrypt text messages and images (if applicable)
        const decryptedMessages = messages.map(msg => {
            let decryptedContent = msg.content; // Default for images
            if (msg.type === 'text' && msg.content && msg.iv) {
                decryptedContent = decryptText(msg.content, msg.iv);
            }
            return {
                _id: msg._id,
                sender: msg.sender,
                recipient: msg.recipient,
                type: msg.type,
                content: decryptedContent, // This will be decrypted text or encrypted image URL/public_id
                imageUrl: msg.imageUrl, // This is the Cloudinary URL for images
                publicId: msg.publicId, // Cloudinary publicId for deletion if needed
                iv: msg.iv, // Keep IV for client-side image decryption
                timestamp: msg.timestamp
            };
        });

        res.json(decryptedMessages);
    } catch (err) {
        console.error('Error fetching messages:', err);
        res.status(500).json({ message: 'Error fetching messages', error: err.message });
    }
});


// --- Socket.IO ---
const userSockets = new Map(); // Map userId to socket.id
const socketUserMap = new Map(); // Map socket.id to userId

io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('set_user_id', async (userId) => {
        if (!userId) {
            console.warn('Received empty userId for socket:', socket.id);
            return;
        }
        userSockets.set(userId, socket.id);
        socketUserMap.set(socket.id, userId);
        socket.join(userId); // Join a room named after the user's ID
        console.log(`User ${userId} connected with socket ID ${socket.id}`);

        // Set user as online
        try {
            await User.findByIdAndUpdate(userId, { isOnline: true, lastOnline: new Date() });
            const friends = await User.findById(userId).select('friends').populate('friends', 'username');
            if (friends) {
                friends.friends.forEach(friend => {
                    io.to(friend._id.toString()).emit('friend_status_update', { userId: userId, isOnline: true });
                });
            }
        } catch (err) {
            console.error('Error updating user online status:', err);
        }
    });

    socket.on('disconnect', async () => {
        console.log('User disconnected:', socket.id);
        const userId = socketUserMap.get(socket.id);
        if (userId) {
            userSockets.delete(userId);
            socketUserMap.delete(socket.id);
            console.log(`User ${userId} disconnected.`);

            // Set user as offline
            try {
                await User.findByIdAndUpdate(userId, { isOnline: false, lastOnline: new Date() });
                const friends = await User.findById(userId).select('friends').populate('friends', 'username');
                if (friends) {
                    friends.friends.forEach(friend => {
                        io.to(friend._id.toString()).emit('friend_status_update', { userId: userId, isOnline: false });
                    });
                }
            } catch (err) {
                console.error('Error updating user offline status:', err);
            }
        }
    });

    // Handle text messages
    socket.on('chat_message', async ({ senderId, recipientId, message }) => {
        try {
            // Encrypt the message before saving and sending
            const { iv, encryptedData } = encryptText(message);

            const newMessage = new Message({
                sender: senderId,
                recipient: recipientId,
                content: encryptedData,
                iv: iv,
                type: 'text'
            });
            await newMessage.save();

            // Emit to both sender and recipient (if online)
            io.to(senderId).emit('new_message', {
                _id: newMessage._id,
                sender: senderId,
                recipient: recipientId,
                type: 'text',
                content: message, // Send decrypted message back to sender for immediate display
                timestamp: newMessage.timestamp
            });

            // Only send encrypted version to recipient
            io.to(recipientId).emit('new_message', {
                _id: newMessage._id,
                sender: senderId,
                recipient: recipientId,
                type: 'text',
                content: encryptedData, // Send encrypted data for recipient to decrypt
                iv: iv,
                timestamp: newMessage.timestamp
            });

        } catch (err) {
            console.error('Error handling chat message:', err);
        }
    });

    // Handle image messages
    socket.on('image_message', async ({ senderId, recipientId, base64Image, originalFileName }) => {
        try {
            // Convert base64 to buffer
            const imageBuffer = Buffer.from(base64Image, 'base64');

            // Encrypt the image buffer
            const { iv, encryptedData } = encryptImage(imageBuffer);

            // Upload the encrypted image to Cloudinary
            const uploadResult = await cloudinary.uploader.upload(`data:image/jpeg;base64,${encryptedData}`, {
                folder: 'foxchat_images',
                // resource_type: 'raw', // Use 'raw' if you want to store it as a generic file without image transformations
                public_id: `${senderId}_${recipientId}_${Date.now()}_${originalFileName.split('.')[0]}`
            });

            const imageUrl = uploadResult.secure_url; // URL of the encrypted image on Cloudinary
            const publicId = uploadResult.public_id; // Public ID for future deletion if needed

            const newMessage = new Message({
                sender: senderId,
                recipient: recipientId,
                type: 'image',
                content: null, // No text content for image messages
                imageUrl: imageUrl, // Store the Cloudinary URL
                publicId: publicId,
                iv: iv // Store the IV for decryption on the client-side
            });
            await newMessage.save();

            // Emit to both sender and recipient
            io.to(senderId).emit('new_message', {
                _id: newMessage._id,
                sender: senderId,
                recipient: recipientId,
                type: 'image',
                imageUrl: imageUrl,
                publicId: publicId,
                iv: iv,
                timestamp: newMessage.timestamp
            });
            io.to(recipientId).emit('new_message', {
                _id: newMessage._id,
                sender: senderId,
                recipient: recipientId,
                type: 'image',
                imageUrl: imageUrl,
                publicId: publicId,
                iv: iv,
                timestamp: newMessage.timestamp
            });

        } catch (err) {
            console.error('Error handling image message:', err);
            socket.emit('message_error', 'Failed to send image.');
        }
    });
});

// Serve static files for production (if using same server for frontend)
// This path might need adjustment based on your deployment strategy
// For Render/Vercel combined, this is not needed if Vercel hosts frontend.
// app.use(express.static('public'));

// app.get('*', (req, res) => {
//     res.sendFile(path.join(__dirname, 'public', 'index.html'));
// });

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));


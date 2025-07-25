// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const cloudinary = require('cloudinary').v2;
const { Buffer } = require('buffer');

// --- Gestori Globali per Errori Non Catturati ---
// Questi catturano errori che altrimenti farebbero crashare il tuo server silenziosamente.
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // In produzione, potresti voler terminare il processo qui (es. process.exit(1);)
    // per far ripartire il servizio e pulire lo stato.
});

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.message, err.stack);
    // È consigliabile terminare il processo e riavviare per evitare stati inconsistenti.
    process.exit(1); // Questo farà sì che Render riavvii il servizio
});


// --- Configurazione Cloudinary ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- Variabili d'ambiente critiche ---
const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // Converti da hex a Buffer
const IMAGE_ENCRYPTION_KEY = Buffer.from(process.env.IMAGE_ENCRYPTION_KEY, 'hex'); // Converti da hex a Buffer

// Controllo per la lunghezza delle chiavi di cifratura (devono essere di 32 byte)
if (ENCRYPTION_KEY.length !== 32 || IMAGE_ENCRYPTION_KEY.length !== 32) {
    console.error('Encryption keys must be 32 bytes (64 hex characters) long.');
    process.exit(1);
}

// --- Funzioni di Cifratura/Decifratura ---
const encrypt = (text, key) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
};

const decrypt = (text, key) => {
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error("Decryption failed:", error.message);
        return null; // Restituisce null o lancia un errore per gestione a monte
    }
};


// --- Connessione a MongoDB ---
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- Schemi e Modelli ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friendRequestsSent: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friendRequestsReceived: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    profilePicture: { type: String } // URL della foto su Cloudinary (cifrato)
});

const messageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true }, // Contenuto cifrato
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);


// --- Inizializzazione Express e Socket.IO ---
const app = express();
const server = http.createServer(app);

// Middleware per il parsing del body delle richieste JSON
app.use(express.json());

// --- Configurazione CORS ---
// *** IMPORTANTE: Per il debugging, accetta tutte le origini. ***
// *** Per la produzione, CAMBIA 'origin: "*"' con l'URL specifico del tuo frontend per sicurezza! ***
app.use(cors({
    origin: '*', // Accetta richieste da QUALSIASI origine per debugging
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Configurazione CORS per Socket.IO (deve essere separata)
const io = socketIo(server, {
    cors: {
        origin: '*', // Accetta QUALSIASI origine per Socket.IO
        methods: ["GET", "POST"],
        credentials: true
    },
    pingInterval: 25000,
    pingTimeout: 60000
});

// --- Middleware per l'Autenticazione JWT ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        console.log('Authentication failed: No token provided');
        return res.status(401).json({ message: 'Authentication token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// --- ROTTE API ---

// Rotta di test (funzionante)
app.get('/api/test', (req, res) => {
    console.log('--> Test route hit');
    res.json({ message: 'Backend is working correctly!' });
});


// Registrazione Utente
app.post('/api/register', async (req, res) => {
    console.log('--> Register route hit');
    const { username, email, password } = req.body;
    console.log('Registering user:', username);
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Password hashed for:', username);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        console.log('User saved successfully:', username);
        res.status(201).json({ message: 'User registered successfully' });
        console.log('Register response sent for:', username);
    } catch (err) {
        console.error('Error during registration for:', username, 'Error:', err.message, 'Code:', err.code);
        if (err.code === 11000) { // Duplicate key error
            return res.status(409).json({ message: 'Username or email already exists' });
        }
        res.status(500).json({ message: 'Error registering user', error: err.message });
    }
});

// Login Utente
app.post('/api/login', async (req, res) => {
    console.log('--> Login route hit');
    const { username, password } = req.body;
    console.log('Attempting login for:', username);
    try {
        const user = await User.findOne({ username });
        if (!user) {
            console.log('Login failed: User not found for:', username);
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        console.log('User found for login:', username);
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Login failed: Password mismatch for:', username);
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        console.log('Password matched for:', username);
        const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        console.log('JWT token generated for:', username);
        res.json({ token, username: user.username, userId: user._id });
        console.log('Login response sent for:', username);
    } catch (err) {
        console.error('Error during login for:', username, 'Error:', err.message);
        res.status(500).json({ message: 'Error logging in', error: err.message });
    }
});

// Ottieni i dettagli dell'utente loggato
app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Decifra l'URL della foto profilo prima di inviarlo al client
        if (user.profilePicture) {
            user.profilePicture = decrypt(user.profilePicture, IMAGE_ENCRYPTION_KEY);
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching user data:', err.message);
        res.status(500).json({ message: 'Error fetching user data', error: err.message });
    }
});

// Ottieni la lista amici
app.get('/api/friends', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('friends', 'username profilePicture');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Decifra le foto profilo degli amici
        const friendsWithDecryptedPics = user.friends.map(friend => {
            if (friend.profilePicture) {
                friend.profilePicture = decrypt(friend.profilePicture, IMAGE_ENCRYPTION_KEY);
            }
            return friend;
        });
        res.json(friendsWithDecryptedPics);
    } catch (err) {
        console.error('Error fetching friends:', err.message);
        res.status(500).json({ message: 'Error fetching friends', error: err.message });
    }
});

// Cerca utenti
app.get('/api/users/search', authenticateToken, async (req, res) => {
    const { query } = req.query;
    try {
        const users = await User.find({
            username: { $regex: query, $options: 'i' },
            _id: { $ne: req.user.id } // Non includere l'utente corrente
        }).select('username profilePicture');

        // Decifra le foto profilo degli utenti cercati
        const usersWithDecryptedPics = users.map(user => {
            if (user.profilePicture) {
                user.profilePicture = decrypt(user.profilePicture, IMAGE_ENCRYPTION_KEY);
            }
            return user;
        });

        res.json(usersWithDecryptedPics);
    } catch (err) {
        console.error('Error searching users:', err.message);
        res.status(500).json({ message: 'Error searching users', error: err.message });
    }
});

// Invia richiesta d'amicizia
app.post('/api/friends/request', authenticateToken, async (req, res) => {
    const { receiverId } = req.body;
    try {
        const sender = await User.findById(req.user.id);
        const receiver = await User.findById(receiverId);

        if (!sender || !receiver) {
            return res.status(404).json({ message: 'Sender or receiver not found' });
        }
        if (sender.friends.includes(receiverId) || receiver.friends.includes(req.user.id)) {
            return res.status(400).json({ message: 'Already friends' });
        }
        if (sender.friendRequestsSent.includes(receiverId)) {
            return res.status(400).json({ message: 'Friend request already sent' });
        }
        if (sender.friendRequestsReceived.includes(receiverId)) {
            return res.status(400).json({ message: 'User has already sent you a friend request, please accept it' });
        }

        sender.friendRequestsSent.push(receiverId);
        receiver.friendRequestsReceived.push(req.user.id);
        await sender.save();
        await receiver.save();

        // Notifica il ricevitore via Socket.IO
        // Decifra la foto del mittente prima di inviarla via socket
        let senderProfilePictureDecrypted = sender.profilePicture ? decrypt(sender.profilePicture, IMAGE_ENCRYPTION_KEY) : null;

        io.to(receiverId).emit('friendRequest', {
            _id: sender._id,
            username: sender.username,
            profilePicture: senderProfilePictureDecrypted
        });

        res.status(200).json({ message: 'Friend request sent' });
    } catch (err) {
        console.error('Error sending friend request:', err.message);
        res.status(500).json({ message: 'Error sending friend request', error: err.message });
    }
});

// Accetta/Rifiuta richiesta d'amicizia
app.post('/api/friends/respond', authenticateToken, async (req, res) => {
    const { senderId, accept } = req.body;
    try {
        const receiver = await User.findById(req.user.id);
        const sender = await User.findById(senderId);

        if (!receiver || !sender) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Rimuovi la richiesta dalle liste di entrambi
        receiver.friendRequestsReceived = receiver.friendRequestsReceived.filter(id => id.toString() !== senderId);
        sender.friendRequestsSent = sender.friendRequestsSent.filter(id => id.toString() !== req.user.id);

        if (accept) {
            receiver.friends.push(senderId);
            sender.friends.push(req.user.id);
            await receiver.save();
            await sender.save();

            // Notifica entrambi via Socket.IO
            let senderProfilePictureDecrypted = sender.profilePicture ? decrypt(sender.profilePicture, IMAGE_ENCRYPTION_KEY) : null;
            let receiverProfilePictureDecrypted = receiver.profilePicture ? decrypt(receiver.profilePicture, IMAGE_ENCRYPTION_KEY) : null;


            io.to(receiver._id).emit('friendAccepted', {
                _id: sender._id,
                username: sender.username,
                profilePicture: senderProfilePictureDecrypted
            });
            io.to(sender._id).emit('friendAccepted', {
                _id: receiver._id,
                username: receiver.username,
                profilePicture: receiverProfilePictureDecrypted
            });

            res.status(200).json({ message: 'Friend request accepted' });
        } else {
            await receiver.save();
            await sender.save();
            res.status(200).json({ message: 'Friend request rejected' });
        }
    } catch (err) {
        console.error('Error responding to friend request:', err.message);
        res.status(500).json({ message: 'Error responding to friend request', error: err.message });
    }
});


// Rotta per i messaggi
app.get('/api/messages/:friendId', authenticateToken, async (req, res) => {
    try {
        const { friendId } = req.params;
        const userId = req.user.id;

        // Recupera i messaggi tra i due utenti, cifrati
        const messages = await Message.find({
            $or: [
                { sender: userId, receiver: friendId },
                { sender: friendId, receiver: userId }
            ]
        }).sort('timestamp');

        // Decifra i contenuti dei messaggi prima di inviarli
        const decryptedMessages = messages.map(msg => ({
            ...msg._doc,
            content: decrypt(msg.content, ENCRYPTION_KEY)
        }));

        res.json(decryptedMessages);
    } catch (err) {
        console.error('Error fetching messages:', err.message);
        res.status(500).json({ message: 'Error fetching messages', error: err.message });
    }
});

// Rotta per caricare immagini profilo
app.post('/api/upload-profile-picture', authenticateToken, async (req, res) => {
    const { imageData } = req.body; // Base64 image data
    try {
        // Carica l'immagine su Cloudinary
        const uploadResult = await cloudinary.uploader.upload(imageData, {
            folder: 'profile_pictures',
            transformation: {
                width: 150,
                height: 150,
                crop: "fill",
                gravity: "face"
            }
        });

        // Cifra l'URL dell'immagine prima di salvarlo nel database
        const encryptedUrl = encrypt(uploadResult.secure_url, IMAGE_ENCRYPTION_KEY);

        // Aggiorna l'URL della foto profilo nel database utente
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        user.profilePicture = encryptedUrl;
        await user.save();

        res.json({ message: 'Profile picture updated', profilePicture: uploadResult.secure_url });

    } catch (err) {
        console.error('Error uploading profile picture:', err.message);
        res.status(500).json({ message: 'Error uploading profile picture', error: err.message });
    }
});

// --- Socket.IO Handlers ---
io.on('connection', (socket) => {
    console.log('A user connected:', socket.id);

    // Associa l'ID utente (dal JWT) all'ID del socket
    socket.on('setUserId', (userId) => {
        socket.join(userId); // Unisci il socket a una room con l'ID utente
        console.log(`User ${userId} joined socket room`);
    });

    socket.on('sendMessage', async (data) => {
        const { senderId, receiverId, content } = data;
        try {
            // Cifra il messaggio prima di salvarlo
            const encryptedContent = encrypt(content, ENCRYPTION_KEY);

            const message = new Message({
                sender: senderId,
                receiver: receiverId,
                content: encryptedContent,
            });
            await message.save();

            // Decifra il messaggio per l'invio via socket, così i client non devono decifrare
            const decryptedContent = decrypt(encryptedContent, ENCRYPTION_KEY);

            // Emetti il messaggio al mittente e al destinatario
            io.to(senderId).emit('newMessage', {
                sender: senderId,
                receiver: receiverId,
                content: decryptedContent,
                timestamp: message.timestamp
            });
            io.to(receiverId).emit('newMessage', {
                sender: senderId,
                receiver: receiverId,
                content: decryptedContent,
                timestamp: message.timestamp
            });
        } catch (error) {
            console.error('Error saving or sending message via socket:', error.message);
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// --- Avvio del Server ---
const PORT = process.env.PORT || 10000; // Render usa process.env.PORT
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

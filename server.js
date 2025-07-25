require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Per hash password
const cloudinary = require('cloudinary').v2; // Per Cloudinary

const app = express();
const server = http.createServer(app);

// Configurazione Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Chiavi di cifratura (DEVONO ESSERE STRINGHE DI 64 CARATTERI ESADECIMALI)
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IMAGE_ENCRYPTION_KEY = process.env.IMAGE_ENCRYPTION_KEY;
const JWT_SECRET = process.env.JWT_SECRET; // JWT Secret

// Verifica che le chiavi siano lunghe 64 caratteri e il JWT secret sia presente
if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    console.error('ERRORE: ENCRYPTION_KEY non è impostata o non è lunga 64 caratteri.');
    process.exit(1);
}
if (!IMAGE_ENCRYPTION_KEY || IMAGE_ENCRYPTION_KEY.length !== 64) {
    console.error('ERRORE: IMAGE_ENCRYPTION_KEY non è impostata o non è lunga 64 caratteri.');
    process.exit(1);
}
if (!JWT_SECRET) {
    console.error('ERRORE: JWT_SECRET non è impostato.');
    process.exit(1);
}

// Configurazione CORS per Express
app.use(cors()); // Permette tutte le origini per ora (puoi restringere in produzione)
app.use(express.json({ limit: '50mb' })); // Per gestire body JSON, aumenta limite per immagini base64
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Per gestire URL-encoded bodies

// Connessione a MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connesso a MongoDB Atlas'))
.catch(err => console.error('Errore di connessione a MongoDB:', err));

// --- MODELLI (Definiti direttamente in server.js per semplicità) ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePicture: { type: String, default: '' }, // URL dell'immagine di profilo
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Array di ID di amici
    friendRequestsSent: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Richieste inviate
    friendRequestsReceived: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Richieste ricevute
}, { timestamps: true });

UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', MessageSchema);


// --- MIDDLEWARE DI AUTENTICAZIONE (per rotte protette) ---
const auth = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
        return res.status(401).json({ message: 'Nessun token, autorizzazione negata' });
    }

    const token = authHeader.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ message: 'Nessun token, autorizzazione negata' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        res.status(401).json({ message: 'Token non valido' });
    }
};


// --- ROTTE API (Definite direttamente in server.js) ---

// 1. Registrazione Utente
app.post('/api/register', async (req, res) => {
    console.log('--> Register route hit');
    const { username, email, password } = req.body;

    try {
        console.log(`Registering user: ${username}`);
        let user = await User.findOne({ $or: [{ username }, { email }] });
        if (user) {
            return res.status(400).json({ message: 'Utente o email già registrati' });
        }

        user = new User({ username, email, password });
        // La password viene hashata nel pre-save hook di Mongoose
        await user.save();
        console.log(`User saved successfully: ${username}`);

        const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        console.log(`Register response sent for: ${username}`);
        res.status(201).json({ message: 'Registrazione avvenuta con successo', token, userId: user._id, username: user.username });
    } catch (err) {
        console.error('Errore nella registrazione:', err);
        res.status(500).json({ message: 'Errore del server', error: err.message });
    }
});

// 2. Login Utente
app.post('/api/login', async (req, res) => {
    console.log('--> Login route hit');
    const { username, password } = req.body;

    try {
        console.log(`Attempting login for user: ${username}`);
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Credenziali non valide' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenziali non valide' });
        }

        const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        console.log(`Login successful for user: ${username}`);
        res.json({ message: 'Login avvenuto con successo', token, userId: user._id, username: user.username });
    } catch (err) {
        console.error('Errore nel login:', err);
        res.status(500).json({ message: 'Errore del server', error: err.message });
    }
});

// 3. Caricamento Immagine Profilo
app.post('/api/upload-profile-picture', auth, async (req, res) => {
    const { imageData } = req.body; // Base64 image data
    try {
        const uploadResult = await cloudinary.uploader.upload(imageData, {
            folder: 'foxchat_profile_pics', // Cartella su Cloudinary
            transformation: [{ width: 150, height: 150, crop: "fill", gravity: "face" }]
        });

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ message: 'Utente non trovato' });
        }

        user.profilePicture = uploadResult.secure_url; // Salva l'URL sicuro di Cloudinary
        await user.save();

        res.json({ message: 'Immagine profilo caricata con successo!', profilePictureUrl: user.profilePicture });
    } catch (error) {
        console.error('Errore nel caricamento immagine profilo:', error);
        res.status(500).json({ message: 'Errore durante il caricamento dell\'immagine.', error: error.message });
    }
});

// 4. Ottieni Dettagli Utente (protetta)
app.get('/api/user', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
                                .populate('friends', 'username profilePicture')
                                .populate('friendRequestsSent', 'username profilePicture')
                                .populate('friendRequestsReceived', 'username profilePicture')
                                .select('-password'); // Non inviare la password
        if (!user) {
            return res.status(404).json({ message: 'Utente non trovato' });
        }
        res.json(user);
    } catch (error) {
        console.error('Errore nel recupero dettagli utente:', error);
        res.status(500).json({ message: 'Errore del server', error: error.message });
    }
});

// 5. Cerca Utenti
app.get('/api/users/search', auth, async (req, res) => {
    const { query } = req.query;
    try {
        const users = await User.find({
            username: { $regex: query, $options: 'i' }, // Ricerca case-insensitive
            _id: { $ne: req.user.userId } // Escludi se stesso
        }).select('username profilePicture');
        res.json(users);
    } catch (error) {
        console.error('Errore nella ricerca utenti:', error);
        res.status(500).json({ message: 'Errore del server', error: error.message });
    }
});

// 6. Invia Richiesta di Amicizia
app.post('/api/friends/request', auth, async (req, res) => {
    const { receiverId } = req.body;
    const senderId = req.user.userId;

    try {
        const sender = await User.findById(senderId);
        const receiver = await User.findById(receiverId);

        if (!sender || !receiver) {
            return res.status(404).json({ message: 'Mittente o destinatario non trovato' });
        }

        if (sender.friends.includes(receiverId)) {
            return res.status(400).json({ message: 'Siete già amici' });
        }
        if (sender.friendRequestsSent.includes(receiverId)) {
            return res.status(400).json({ message: 'Richiesta di amicizia già inviata' });
        }
        if (receiver.friendRequestsReceived.includes(senderId)) {
            return res.status(400).json({ message: 'Richiesta di amicizia già ricevuta' });
        }

        // Se il ricevitore ha già inviato una richiesta al mittente, accettala automaticamente
        if (sender.friendRequestsReceived.includes(receiverId)) {
            await User.findByIdAndUpdate(senderId, {
                $pull: { friendRequestsReceived: receiverId },
                $addToSet: { friends: receiverId }
            });
            await User.findByIdAndUpdate(receiverId, {
                $pull: { friendRequestsSent: senderId },
                $addToSet: { friends: senderId }
            });
            io.to(senderId).emit('friendAccepted', { _id: receiverId, username: receiver.username });
            io.to(receiverId).emit('friendAccepted', { _id: senderId, username: sender.username });
            return res.status(200).json({ message: 'Richiesta di amicizia accettata automaticamente! Siete ora amici.' });
        }

        sender.friendRequestsSent.push(receiverId);
        receiver.friendRequestsReceived.push(senderId);

        await sender.save();
        await receiver.save();

        // Notifica il destinatario tramite Socket.IO
        io.to(receiverId).emit('friendRequest', { _id: sender._id, username: sender.username });

        res.status(200).json({ message: 'Richiesta di amicizia inviata!' });
    } catch (error) {
        console.error('Errore nell\'invio richiesta amicizia:', error);
        res.status(500).json({ message: 'Errore del server', error: error.message });
    }
});

// 7. Rispondi a Richiesta di Amicizia
app.post('/api/friends/respond', auth, async (req, res) => {
    const { senderId, accept } = req.body;
    const receiverId = req.user.userId; // Chi sta rispondendo

    try {
        const receiver = await User.findById(receiverId);
        const sender = await User.findById(senderId);

        if (!receiver || !sender) {
            return res.status(404).json({ message: 'Utente non trovato' });
        }

        if (!receiver.friendRequestsReceived.includes(senderId)) {
            return res.status(400).json({ message: 'Nessuna richiesta di amicizia da questo utente' });
        }

        if (accept) {
            // Rimuovi dalla lista richieste ricevute e aggiungi agli amici
            receiver.friendRequestsReceived.pull(senderId);
            receiver.friends.push(senderId);
            // Aggiorna anche il mittente
            sender.friendRequestsSent.pull(receiverId);
            sender.friends.push(receiverId);

            await receiver.save();
            await sender.save();

            // Notifica il mittente tramite Socket.IO
            io.to(senderId).emit('friendAccepted', { _id: receiver._id, username: receiver.username });
            res.status(200).json({ message: 'Richiesta di amicizia accettata!' });
        } else {
            // Rifiuta: rimuovi solo dalla lista richieste ricevute
            receiver.friendRequestsReceived.pull(senderId);
            sender.friendRequestsSent.pull(receiverId); // Rimuovi anche da richieste inviate del mittente

            await receiver.save();
            await sender.save();

            res.status(200).json({ message: 'Richiesta di amicizia rifiutata.' });
        }
    } catch (error) {
        console.error('Errore nel rispondere alla richiesta di amicizia:', error);
        res.status(500).json({ message: 'Errore del server', error: error.message });
    }
});

// 8. Ottieni Lista Amici
app.get('/api/friends', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('friends', 'username profilePicture');
        if (!user) {
            return res.status(404).json({ message: 'Utente non trovato' });
        }
        res.json(user.friends);
    } catch (error) {
        console.error('Errore nel recupero della lista amici:', error);
        res.status(500).json({ message: 'Errore del server', error: error.message });
    }
});

// 9. Ottieni Messaggi tra due utenti
app.get('/api/messages/:friendId', auth, async (req, res) => {
    const { friendId } = req.params;
    const userId = req.user.userId;

    try {
        const messages = await Message.find({
            $or: [
                { sender: userId, receiver: friendId },
                { sender: friendId, receiver: userId }
            ]
        }).sort({ timestamp: 1 }); // Ordina per data crescente

        res.json(messages);
    } catch (error) {
        console.error('Errore nel recupero messaggi:', error);
        res.status(500).json({ message: 'Errore del server', error: error.message });
    }
});

// ROOT endpoint (per testare che il server sia attivo)
app.get('/', (req, res) => {
    res.send('Server running! Connect OK');
});

// Endpoint di test per CORS e /api/register
app.get('/api/register', (req, res) => {
    res.send('Connect OK /api/register');
});


// Gestione errori globale
app.use((err, req, res, next) => {
    console.error(err.stack); // Stampa lo stack trace completo dell'errore
    res.status(err.statusCode || 500).json({
        message: err.message || 'Qualcosa è andato storto!',
        error: process.env.NODE_ENV === 'production' ? {} : err.stack // Non mostrare stack in produzione
    });
});

// Socket.IO
const io = new Server(server, {
    cors: {
        origin: "*", // Permetti connessioni da qualsiasi origine per il frontend
        methods: ["GET", "POST"]
    }
});

io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error: Token missing'));
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        next();
    } catch (error) {
        return next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.userId}`);

    socket.join(socket.userId); // Ogni utente si unisce a una stanza con il proprio ID

    socket.on('sendMessage', async ({ senderId, receiverId, content }) => {
        try {
            // Salva il messaggio nel database
            const message = new Message({
                sender: senderId,
                receiver: receiverId,
                content: content, // Contenuto già cifrato dal frontend
                timestamp: new Date()
            });
            await message.save();

            // Invia il messaggio al mittente e al destinatario
            // Il messaggio deve essere decifrato solo quando viene visualizzato sul frontend
            io.to(senderId).emit('newMessage', message);
            io.to(receiverId).emit('newMessage', message);
            console.log(`Message sent from ${senderId} to ${receiverId}`);
        } catch (error) {
            console.error('Error sending message:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.userId}`);
    });
});


const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// models/Message.js
const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    receiver: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    message: { // Contiene il testo criptato (IV:ciphertext)
        type: String,
        default: null
    },
    imageUrl: { // Contiene l'URL dell'immagine criptato (IV:ciphertext)
        type: String,
        default: null
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Message', MessageSchema);

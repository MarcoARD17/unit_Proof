// models/user.js
//Romo Delgado
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const SALT_ROUNDS = 10;// cambio al nombre de la variable para saber que es

const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String,
        maxlength: 100
    },
    lastname: {
        type: String,
        maxlength: 100
    },
    token: {
        type: String
    }
});

// Encriptar la contraseña antes de guardar el usuario
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Método para comparar contraseñas en el Login

userSchema.methods.comparePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password); //aqui regresa verdadero o falso
};
// Generar Token JWT al iniciar sesión
userSchema.methods.generateToken = async function () {
    const token = jwt.sign({ _id: this._id.toHexString() }, config.SECRET);
    this.token = token;
    await this.save();
    return token;
};

// Método estático para validar un usuario mediante su Token
userSchema.statics.findByToken = async function (token) {
    try {
        const decode = jwt.verify(token, config.SECRET);
        return await this.findOne({ _id: decode._id, token });//busca por id decodificado del token y por token, como token:token
    } catch (error) {
        return null;
    }
};

// Eliminar token en el Logout
userSchema.methods.deleteToken = async function () {
    return await this.updateOne({ $unset: { token: 1 } });
};

const User = mongoose.model('User', userSchema);

module.exports = User;
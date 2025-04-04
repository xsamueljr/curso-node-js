import crypto from 'node:crypto'

import DBLocal from 'db-local'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { SALT_ROUNDS, SECRET_KEY } from './config'

const { Schema } = new DBLocal({ path: 'db' })

const User = Schema('User', {
    _id: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true }
})


export class UserRepository {

    static async create({ username, password }) {
        Validation.username(username)
        Validation.password(password)

        const user = User.findOne({ username })
        if (user) throw new Error('User already exists')
        
        const id = crypto.randomUUID()
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

        User.create({
            _id: id,
            username,
            password: hashedPassword
        }).save()

        return id
    }
    static async login({ username, password }) {
        Validation.username(username)
        Validation.password(password)

        const user = User.findOne({ username })
        if (!user) throw new Error('User not found')

        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if (!isPasswordCorrect) throw new Error('Invalid password')
        
        const token = jwt.sign({ id: user._id }, SECRET_KEY)
        return token
    }
}

class Validation {
    static username(username) {}
    static password(password) {}
}
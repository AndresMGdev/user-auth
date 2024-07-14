import express from 'express'
import { PORT, SECRET_JWT_KEY } from './config.js'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import { UserRepository } from './model/userRespository.js'

const app = express()

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

app.get('/', (req, res) => {
  const token = req.cookies.access_token

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    if (!token) {
      return res.status(403).send('Access not authorized')
    }
    res.render('index', data)
  } catch (err) {
    res.render('index')
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await UserRepository.login({ email, password })
    const token = jwt.sign({
      id: user._id,
      firstname: user.firstname,
      lastname: user.lastname
    }, SECRET_JWT_KEY, {
      expiresIn: '1h'
    })
    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60
      })
      .send({ token })
  } catch (err) {
    res.status(401).send({ error: err.message })
  }
})

app.post('/register', async (req, res) => {
  const {
    email,
    firstname,
    lastname,
    typeId,
    numberPhone,
    identification,
    address,
    password
  } = req.body

  console.log(req.body)

  try {
    const id = await UserRepository.create({
      email,
      firstname,
      lastname,
      typeId,
      numberPhone,
      identification,
      address,
      password
    })
    res.send({ id })
  } catch (err) {
    res.status(400).send({ error: err.message })
  }
})

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    })
    .send({ message: 'Logged out successfully' })
})

app.get('/profile', (req, res) => {
  const token = req.cookies.access_token
  if (!token) {
    return res.status(403).send('Access not authorized')
  }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    console.log(data)
    res.render('profile', data)
  } catch (err) {
    res.status(401).send('Access not authorized')
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})

import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, requires: true },
  email: { type: String, requires: true },
  firstname: { type: String, requires: true },
  lastname: { type: String, requires: true },
  typeId: { type: String, requires: true },
  identification: { type: String, requires: true },
  numberPhone: { type: String, requires: true },
  address: { type: String, requires: true },
  password: { type: String, requires: true },
  isDelete: { type: Boolean }
})

export class UserRepository {
  static async create ({ email, firstname, lastname, typeId, identification, numberPhone, address, password }) {
    Validation.email(email)
    Validation.password(password)
    Validation.fullname(firstname, lastname)
    Validation.numsRegex(numberPhone, identification)
    Validation.address(address)

    const uEmail = User.findOne({ email })
    if (uEmail) throw new Error('email already exists')

    const uIdentification = User.findOne({ identification })
    if (uIdentification) throw new Error('identification already exists')

    const uPhone = User.findOne({ numberPhone })
    if (uPhone) throw new Error('number phone already exists')

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hashSync(password, 10)

    User.create({
      _id: id,
      email,
      password: hashedPassword,
      firstname,
      lastname,
      typeId,
      numberPhone,
      identification,
      address,
      isDelete: true
    }).save()

    return id
  }

  static async login ({ email, password }) {
    Validation.email(email)
    Validation.password(password)

    const user = User.findOne({ email })
    if (!user) throw new Error('email does not exist')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('password is invalid')

    const { password: _, ...publicUser } = user

    return publicUser
  }
}

class Validation {
  static password (password) {
    if (typeof password !== 'string' && password.length < 6) throw new Error('password must be at least 6 characters long')
  }

  static email (email) {
    const validEmail = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i
    if (!validEmail.test(email)) throw new Error('you must enter a valid email address')
  }

  static fullname (firstname, lastname) {
    if (typeof firstname !== 'string' || firstname.length < 2) throw new Error('firstname must be at least 2 characters long')

    if (typeof lastname !== 'string' || lastname.length < 2) throw new Error('lastname must be at least 2 characters long')
  }

  static typeId (typeId) {
    const validTypeIds = ['CC', 'TI', 'RC', 'CE', 'CI', 'DNI']
    if (!validTypeIds.includes(typeId)) throw new Error('You must choose a valid document type')
  }

  static numsRegex (numberPhone, identification) {
    function isStringNumeric (str) {
      const numericRegex = /^[0-9]+$/

      return numericRegex.test(str)
    }
    if (!isStringNumeric(numberPhone)) throw new Error('Required valid number phone, phone must be a number')

    if (!isStringNumeric(identification)) throw new Error('Required valid identification, identification must be a number')
  }

  static address (address) {
    if (typeof address !== 'string' && address.length < 5) throw new Error('address must be at least 5 characters long')
  }
}

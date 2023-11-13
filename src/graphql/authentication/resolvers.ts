import { GraphQLError } from 'graphql';
import jwt from 'jsonwebtoken'
import { GqlResolvers } from '../../generated/graphql';
import db, { genId } from '../../modules/db';
import { DateTime } from 'luxon'
import { nanoid } from 'nanoid';
import bcrypt from 'bcrypt'
import invariant from 'invariant';

const SALT_ROUNDS = process.env.NODE_ENV === 'test' ? 1 : 10
const authResolvers: GqlResolvers = {
  Mutation: {
    requestSignUp: async (_, {email}) => {
      // Does user exists
      const user = await db.user.findUnique({where: {email}})
      if (user) throw new GraphQLError('User already exists')

      // Does request exists
      await db.signUpRequest.deleteMany({where: {email}})

      // create new signup request
      const token = nanoid(36)
      await db.signUpRequest.create({
        data: {
          id: genId(),
          email,
          tokenHash: await bcrypt.hash(token, SALT_ROUNDS),
          expiresAt: DateTime.now().plus({minutes: 10}).toJSDate()
        }
      })

      // send token to user
      if (process.env.NODE_ENV === 'development') {
        console.log('Token: ', token)
      }
      return { success: true }
    },

    signUp: async (_, {token, email, password}) => {

      const request = await db.signUpRequest.findUnique({where: {email}})
      if (!request) throw new GraphQLError('Sign up request not found')
      if (request.redeemedAt || request.expiresAt < new Date())
        throw new GraphQLError('Signup request expired')

      // compare token with tokenhash
      const validToken = await bcrypt.compare(token, request.tokenHash)
      if (!validToken) throw new GraphQLError('Invalid token')

      // For security reasons, it has been moved down to here
      const existingUser = await db.user.findUnique({where: {email}})
      if (existingUser) throw new GraphQLError('User already exists!')
      
      // create user
      const [user] = await db.$transaction([
        db.user.create({
        data: {
          id: genId(),
          email,
          passwordHash: await bcrypt.hash(password, SALT_ROUNDS)
        }
      }),
     
      db.signUpRequest.update({
          where: {id: request.id},
          data: { redeemedAt: new Date()}
        })
      ])

      // Generate authToken
      invariant(process.env.JWT_SECRET, 'JWT_SECRET not set')
      const authToken = jwt.sign({ userId: user.id}, process.env.JWT_SECRET)
      return { authToken }
    },
    // signIn: () => {},
  },
};

export default authResolvers;

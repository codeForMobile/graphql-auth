import { ApolloServer } from '@apollo/server';
import { startStandaloneServer } from '@apollo/server/standalone';
import { typeDefs, resolvers } from './graphql';
import { GqlContext } from './graphql/types';
import Auth from './modules/auth';
import { GraphQLError } from 'graphql';

const server = new ApolloServer<GqlContext>({ typeDefs, resolvers });

const port = Number(process.env.PORT ?? 8080);
const startServer = async () => {
  const { url } = await startStandaloneServer(server, {
    listen: { host: '0.0.0.0', port },
    context: async ({ req }) => {
      console.log(req.headers)
      const authToken = req.headers.authorization?.split(' ')[1]
      if (!authToken) return { currentUser: null };
      try {
        const user = await Auth.verifyAuthToken(authToken)
        console.log('currentUser', user)
        return { currentUser: user}
      } catch (_) {
        throw new GraphQLError('Invalid auth token', {
          extensions: {code: 'Not_Authorized'}
        })
      }
    },
  });
  console.log(`Server running at ${url}`);
};
startServer();

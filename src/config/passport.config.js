import passport from 'passport';
import passportLocal from 'passport-local';
import GitHubStrategy from 'passport-github2';
import { createHash, isValidPassword } from '../utils.js';
import { cartManager, userManager } from '../services/factory.js';
import { UserDTO } from '../services/dao/dto/user.dto.js';
import userModel from '../services/dao/db/models/user.model.js';

const LocalStrategy = passportLocal.Strategy;

const initializePassport = () => {
    // GitHubStrategy
    passport.use(new GitHubStrategy(
        {
            clientID: '186faacf543b051a48a7',
            clientSecret: '0abeed24e7dbc1414689f406c6af843f2b60ddbf',
            callbackURL: 'http://localhost:3000/auth/github/callback'
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const user = await userManager.getUserByEmail(profile._json.email);
                if (!user) {
                    const cartId = await cartManager.createCart();
                    const cartParsed = JSON.parse(cartId);
                    let newUser = {
                        first_name: profile._json.name,
                        last_name: '{GitHub}',
                        age: '',
                        email: profile._json.email,
                        password: '',
                        registerMethod: "GitHub",
                        role: "Usuario",
                        cartId: cartParsed.createdCartId
                    };
                    
                    const result = await userManager.createUser(new UserDTO(newUser));
                    result.role = "Usuario";
                    done(null, result);
                } else {
                    user.role = "Usuario";
                    return done(null, user);
                }
            } catch (error) {
                return done(error);
            }
        }
    ));

    // LocalStrategy para registro
    passport.use('register', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' },
        async (req, email, password, done) => {
            const { first_name, last_name, age } = req.body;
            try {
                const exists = await userManager.getUserByEmail(email);
                if (exists) {
                    return done(null, false);
                }
                const cartId = await cartManager.createCart();
                const cartParsed = JSON.parse(cartId);
                const user = {
                    first_name,
                    last_name,
                    email,
                    age,
                    password: createHash(password),
                    registerMethod: "App-Local",
                    role: "Usuario",
                    cartId: cartParsed.createdCartId
                };
                const result = await userManager.createUser(new UserDTO(user));
                return done(null, result);
            } catch (error) {
                return done("ERROR: " + error);
            }
        }
    ));

    // LocalStrategy para login
    passport.use('login', new LocalStrategy(
        { passReqToCallback: true, usernameField: 'email' },
        async (req, email, password, done) => {
            try {
                let user = await userManager.getUserByEmail(email);
                if (!user || !isValidPassword(user, password)) {
                    return done(null, false);
                }
                return done(null, user);
            } catch (error) {
                return done(error);
            }
        }
    ));

    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await userManager.getUserById(id);
            done(null, user);
        } catch (error) {
            console.error("ERROR: " + error);
        }
    });
};

export default initializePassport;

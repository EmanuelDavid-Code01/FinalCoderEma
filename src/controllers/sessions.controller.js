import passport from "passport";
import { productManager } from "../services/factory.js";
import { userManager } from "../services/factory.js"
const registerMiddleWareLocal = passport.authenticate('register', { failureRedirect: '/api/sessions/fail-register', successRedirect: '/users/login' });

const loginMiddleWareLocal = passport.authenticate('login', { failureRedirect: '/api/sessions/fail-login'});

const postRegisterController = async (req, res) => {
        req.logger.debug(`${new Date().toLocaleString()}: ${req.body.email} registered successfully`);
        res.status(200).send({ status: 'ok', message: 'User created successfully' });
}

const postLoginController = async (req, res) => {
        const user = req.user
        if (!user) {
            res.status(401).send({ status: 'error', message: 'Cannot login. Something really bad happened... =/' });
        } else {
            req.session.user = {
                id: user._id,
                name: `${user.first_name} ${user.last_name}`,
                email: user.email,
                age: user.age,
                role: user.role,
                cartId: user.cartId
            }
            await userManager.setConnectionTime(req.session.user.id);
            req.logger.debug(`${new Date().toLocaleString()}: ${req.session.user.name} logged in successfully`);
            res.status(200).send({ status: 'ok', message: 'User logged in successfully', user });
        }
}

const githubAuthenticateMiddleWare = passport.authenticate('github', {scope: ['user:email']});


const getDummyFunction = async (req, res) => {
    //no hace nada
}

const githubCallbackMiddleWare = passport.authenticate('github', {failureRedirect: '/api/sessions/fail-gh'});


const getGitHubCallbackController = async (req, res) => {
        const user = req.user
        if (!user) {
            res.status(401).send({ status: 'error', message: 'Cannot login. Something really bad happened... =/' });
        } else {
            req.session.user = {
                id: user._id,
                name: `${user.first_name} ${user.last_name}`,
                email: user.email,
                age: user.age,
                role: user.role,
                cartId: user.cartId
            }
            await userManager.setConnectionTime(req.session.user.id);
            req.logger.debug(`${new Date().toLocaleString()}: ${req.session.user.name} logged in successfully through GitHub`);
            res.redirect('/products');
        }
    
}

const getFailRegisterController = (req, res) => {
    res.render('error', { error: 'No se pudo registrar el usuario en forma Local. Verifica los datos y vuelve a intentarlo.'});
}

const getFailLoginController = (req, res) => {
    res.render('error', { error: 'No se pudo iniciar sesión en forma Local. Verifica los datos y vuelve a intentarlo.'});
}

const getFailGHController = (req, res) => {
    res.render('error', { error: 'No se pudo iniciar sesión/registrarse con GitHub'});
}

const isUserMiddleware = (req, res, next) => {
    if (!req.session.user || (req.session.user.role !== 'Usuario' && req.session.user.role !== 'Premium')) {
        req.logger.warning(`${new Date().toLocaleString()}: Se debe tener perfil de Usuario para ejecutar esta tarea`);
        res.render('denied', { rol: 'no ser Usuario'})
    } else {
        next();
    }
}

const isAdminMiddleware = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'Admin') {
        res.render('denied', { rol: 'no ser Administrador'})
        req.logger.warning(`${new Date().toLocaleString()}: Se debe tener perfil de Administrador para ejecutar esta tarea`);
    } else {
        next();
    } 
}

const isPremiumMiddleware = (req, res, next) => {
    if (!req.session.user || req.session.user.role !== 'Premium') {
        res.render('denied', { rol: 'no ser Administrador'})
        req.logger.warning(`${new Date().toLocaleString()}: Se debe tener perfil de Premium para ejecutar esta tarea`);
    } else {
        next();
    } 
}

const isPremiumOrAdminMiddleware = (req, res, next) => {
    if (!req.session.user || (req.session.user.role !== 'Premium' && req.session.user.role !== 'Admin')) {
        console.log(req.session.user.role);
        res.render('denied', { rol: 'no ser Premium'})
        req.logger.warning(`${new Date().toLocaleString()}: Se debe tener perfil de Premium/Administrador para ejecutar esta tarea`);
    } else {
        next();
    } 
}

const canAddProductToCart = async (req, res, next) => {
    if (!req.session.user) {
        req.logger.warning(`${new Date().toLocaleString()}: No se puede agregar un producto al carrito sin estar logueado`);
        return "{status: 'failed', message: 'No se pudo agregar el producto al carrito. No se encuentra logueado'}";
    } else {
    if (req.session.user.role === 'Usuario') {
        next();
    } else if (req.session.user.role === 'Premium') {
        const productId = req.params.pid;
        const product = await productManager.getProductById(productId);
        if (product.owner === req.session.user.id) {
            req.logger.warning(`${new Date().toLocaleString()}: No se puede agregar un producto propio al carrito`);
            return "{status: 'failed', message: 'No se pudo agregar el producto al carrito. El producto es propio'}";
        } else {
            next();
        }
    } else if (req.session.user.role === 'Admin') {
        req.logger.warning(`${new Date().toLocaleString()}: Se debe tener perfil de Usuario para ejecutar esta tarea. Usted es ${req.session.user.role}`);
        return "{status: 'failed', message: 'No se pudo agregar el producto al carrito. Usted es Administrador'}";
    }
}
}

const isProfileComplete = async (req, res, next) => {
    let profileFull = false;
    const user = await userManager.getUserById(req.params.uid);
    let uploadedDocuments = Array();
    if (!user.documents) {
        profileFull = false;
    } else {
        for (const document in user.documents) {
            uploadedDocuments.push(user.documents[document].name);
        }
        if (uploadedDocuments.includes("accountDocument") && uploadedDocuments.includes("addressDocument") && uploadedDocuments.includes("identificationDocument")) {
            profileFull = true;
        }
    }
    if (!profileFull) {
        req.logger.warning(`${new Date().toLocaleString()}: No se puede acceder a esta página sin completar el perfil`);
        res.status(400).send({ status: 'failed', message: 'No se puede realizar esta acción sin completar el perfil' });
    } else {
        next();
    }

}

export { registerMiddleWareLocal, loginMiddleWareLocal, postRegisterController, postLoginController, githubAuthenticateMiddleWare, getDummyFunction, githubCallbackMiddleWare, getGitHubCallbackController, getFailRegisterController, getFailLoginController, getFailGHController, isUserMiddleware, isAdminMiddleware, isPremiumMiddleware, isPremiumOrAdminMiddleware, canAddProductToCart, isProfileComplete }
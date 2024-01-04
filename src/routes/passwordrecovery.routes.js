import { Router } from 'express';
import { getRecoveryLink, resetPassword, validRecoveryAttemptMiddleWare, renderForgottenPassword, postResetPassword } from '../controllers/passwordrecovery.controllers.js';

const router = Router();

//GET
//Recibe un id de recupero de contraseña y si el mismo está vigente, le da curso a resetPassword
router.get('/reset-password/:requestId', validRecoveryAttemptMiddleWare, resetPassword);

//Lleva a la UI para solicitar el recupero de contraseña
router.get('/password/:userEmail', getRecoveryLink);
router.get('/forgot-password', renderForgottenPassword)

//POST
router.post('/password', postResetPassword);
export default router;
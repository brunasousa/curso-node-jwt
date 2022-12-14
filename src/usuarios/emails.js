const nodemailer = require('nodemailer');

const configuracaoEmailProducao = (contaTeste) => ({
    host: process.env.EMAIL_HOST,
    auth: {
        user: process.env.EMAIL_USUARIO,
        pass: process.env.EMAIL_SENHA
    },
    secure: true
});

const configuracaoEmailTeste = (contaTeste) => ({
    host: 'smtp.ethereal.email',
    auth: contaTeste,
});

async function criaConfiguracaoEmail() {
    if (process.env.NODE_ENV === 'production') {
        return configuracaoEmailProducao();
    } else {
        const contaTeste = await nodemailer.createTestAccount();
        return configuracaoEmailTeste(contaTeste);
    }
}

class Email {

    async enviaEmail() {
        const configuracaoEmail = await criaConfiguracaoEmail();
        const transportador = nodemailer.createTransport(configuracaoEmail);
        const info = await transportador.sendMail(this);

        if (process.env.NODE_ENV === 'production') {
            console.log('URL: '+nodemailer.getTestMessageUrl(info))
        }
    }
}

class EmailVerificacao extends Email {
    constructor(usuario, endereco) {
        super();
        this.from = '"Blog do Código" <noreplay@blogdocodigo.com.br>';
        this.to = usuario.email;
        this.subject = 'Verificacao de Email';
        this.text = `Olá! Verifique o seu e-mail aqui: ${endereco}`;
        this.html =  `<h1>Olá!</h1> Verifique o seu e-mail aqui: <a href="${endereco}">${endereco}</a>`;
    }
}

module.exports = { EmailVerificacao };
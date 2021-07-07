console.log('[DBH] Loading authentication...')
const fatalErrorBanner = document.getElementById('fatalError');
const errorBanner = document.getElementById('error');

const urlSearchParams = new URLSearchParams(window.location.search);
const params = Object.fromEntries(urlSearchParams.entries());
if (fatalErrorBanner) {
    if (!params.service) {
        fatalErrorBanner.innerHTML = 'ERROR MISSING SERVICE';
        fatalErrorBanner.classList = ["redNote"];
        console.log('[DBH] ERROR: no service')
    } else {
        const service = document.getElementById('service');
        service.value = params.service;
    }
    if (params.error) {
        errorBanner.innerHTML = params.error; //'Those credentials do not match any accounts!';
        errorBanner.classList = ["redNote"];
    };
    grecaptcha.ready(function() {
        // do request for recaptcha token
        // response is promise with passed token
            grecaptcha.execute('6Lc6dnwbAAAAAO4ipZBV07SNaehahLi61GDpxPkJ', {action:'validate_captcha'})
                    .then(function(token) {
            // add token value to form
            document.getElementById('g-recaptcha-response').value = token;
        });
    });
} else if (!params.email) {
    const token = document.getElementById('token');
    token.value = params.token;
    grecaptcha.ready(function() {
        // do request for recaptcha token
        // response is promise with passed token
            grecaptcha.execute('6Lc6dnwbAAAAAO4ipZBV07SNaehahLi61GDpxPkJ', {action:'validate_captcha'})
                    .then(function(token) {
            // add token value to form
            document.getElementById('g-recaptcha-response').value = token;
        });
    });
}

const text = document.getElementById('text');
if (params.email && text) {
    text.innerHTML = `You need to verify your email address! An email has been sent to ${params.email} please open the link inside. You will only have to do this once`;
}

function onsubmitRegister() {

    localStorage.setItem('register', JSON.stringify({
        username: document.getElementById('username').value,
        email: document.getElementById('email').value
    }))
    
};
function onsubmitLogin() {
    console.log('dsadsa')
    localStorage.setItem('login', JSON.stringify({
        username: document.getElementById('username').value
    }))
};
const express = require('express')
const morgan = require('morgan')
const cookieParser = require('cookie-parser')
const path = require('path')
const crypto = require('crypto')
const fs = require('fs')
const jwt = require('jsonwebtoken')

process.on('uncaughtException', function (err) {
    console.error(err);
});

const jwtSecret = crypto.randomBytes(128).toString('hex')

function createSession(id, expirationSeconds = 24 * 60 * 60) {
    const value = jwt.sign({ id }, jwtSecret, { expiresIn: expirationSeconds })
    return {
        name: 'session',
        value,
        options: { httpOnly: true, maxAge: expirationSeconds * 1000 }
    }
}

function isSessionValid(req) {
    if (!req.cookies) {
        return false
    }
    const token = req.cookies['session']
    if (!token) {
        return false
    }
    try {
        const { id } = jwt.verify(token, jwtSecret)
        if (!id) {
            return false
        }
        const user = User.find(id)
        if (!user) {
            return false
        }
        return user
    } catch (err) {
        return false
    }
}

const state = (() => {
    const users = fs.readFileSync('state').toString('utf-8').split('\n')
    return {
        users
    }
})()

const persistUser = (user) => fs.appendFileSync('state', user.toLine())

function sha256(input, rounds) {
    if (input == null) return null
    if (rounds <= 0) return input
    else return sha256(crypto.createHash('sha256').update(input).digest('base64'), rounds - 1)
}

function html(content = "") {
    return `
    <!doctype html>
    <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="stylesheet" href="/bulma/bulma.min.css">
        </head>
        <body>
            ${content}
        </body>
    </html>`.trim()
}

const User = new (class {
    constructor() {
        this.db = new Map()
    }

    find(id) {
        return this.db.get(id)
    }

    findOrCreate(id, name = "", role) {
        if (!id) {
            return null
        }
        if (this.db.has(id)) {
            return this.db.get(id)
        }
        const password = crypto.randomBytes(64).toString('hex')
        const user = new (class {
            constructor(id, name, role) {
                this.id = id
                this.name = name
                this.balance = 1000
                this.credentials = {
                    password: sha256(password, 200),
                    token: null,
                }
                this.role = role
                this.level = 1
                this.status = "Hello world 🌎"
            }

            toLine() {
                return `\n${this.id}:${this.name}:${this.role}`
            }
        })(id, name, role)
        this.db.set(id, user)
        return user
    }

    fromLine(line) {
        const [id, name, role] = line.split(":")
        return User.findOrCreate(id, name, role === "undefined" ? undefined : role)
    }
})

state.users.reverse().forEach(row => {
    User.fromLine(row)
})

const app = express()

app.use(morgan('tiny')) // logs
app.use(cookieParser())

app.get('/', (req, res) => {
    const user = isSessionValid(req)
    if (!user) {
        res.redirect('/login')
        return
    }

    res.send(html(`
        <style>
            a:hover {
                color: #3850b7 !important;
            }
            .sticky-header {
                position: sticky;
                top: 0;
                background-color: #fff;
                z-index: 1;
            }
            .chat-container {
                max-width: 600px;
                margin: 0 auto;
                border-radius: 8px;
                background: #eee;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }
            .chat-header {
                background-color: #00d1b2;
                color: #fff;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 15px;
            }
            .chat-messages {
                max-height: 500px;
                overflow-y: auto;
                padding: 15px;
            }
            .chat-message {
                margin-bottom: 15px;
            }
            .user-message {
                background-color: #00d1b2;
                color: #fff;
                border-radius: 20px 20px 0 20px;
                padding: 10px 15px;
                max-width: 80%;
                align-self: flex-end;
            }
            .error-message {
                background-color: #cd0000;
                color: #fff;
                border-radius: 20px 20px 0 20px;
                padding: 10px 15px;
                max-width: 80%;
                align-self: flex-end;
            }
            .bot-message {
                background-color: #f5f5f5;
                color: #fff;
                border-radius: 20px 20px 20px 0;
                padding: 10px 15px;
                max-width: 80%;
                align-self: flex-start;
            }
            .user-message.bubble {
                background-color: #007bff;
            }
            .bot-message.bubble {
                background-color: #6c757d;
            }
        </style>
        <div class="sticky-header">
            <section class="hero is-primary is-small">
                <div class="hero-body">
                    <div class="container">
                    <center>
                    <a class="is-size-5" onclick="(() => { document.querySelector('.modal').classList.add('is-active'); if (chat) chat.scrollTop = chat.scrollHeight })()">
                        The cringe lord is now online!
                    </a>
                    </center>
                    </div>
                </div>
            </section>
        </div>
        <div class="container">
            <section class="section">
            <h1 class="is-size-3 mb-3">Welcome ${user.name}!</h1>
            <div class="section">
                <div class="box">
                    <h2 class="title is-5">Current Balance</h2>
                    <p class="subtitle is-5">${user.balance} credits</p>
                </div>
                <a class="button is-primary" href="/user">Access User Customization ™️</a>
                <a class="button is-primary" href="/credit">Add Credit</a>
            </div>
            </section>
        </div>
        <div class="modal">
            <div class="modal-background" onclick="(() => { document.querySelector('.modal').classList.remove('is-active') })()"></div>
            <div class="modal-content">
                <div class="chat-container">
                    <div class="chat-header">
                        Chat with the cringe lord
                    </div>
                    <div class="chat-messages" id="chat-messages">
                        <div class="chat-message bot-message bubble">
                            Hi there! How can I assist you today?
                        </div>
                        <div class="chat-message user-message bubble">
                            Sure, I have a question.
                        </div>
                    </div>
                    <script>
                        const chat = document.querySelector('#chat-messages')

                        function createBubble(message, type) {
                            const bubble = document.createElement('div')
                            bubble.classList.add('chat-message', type, 'bubble')
                            bubble.innerText = message
                            return bubble
                        }

                        function sendMessage(message) {
                            const userBubble = createBubble(message, 'user-message')
                            chat.appendChild(userBubble)
                            fetch('/chat?msg=' + encodeURIComponent(message))
                                .then((res) => {
                                    if (res.status !== 200) {
                                        throw new Error(res.status)
                                    }
                                    return res.json()
                                })
                                .then((text) => {
                                    const messageBubble = createBubble(text, 'bot-message')
                                    chat.appendChild(messageBubble)
                                })
                                .catch((err) => {
                                    const errorBubble = createBubble('An error occured: ' + err.toString(), 'error-message')
                                    chat.appendChild(errorBubble)
                                })
                                .finally(() => {
                                    chat.scrollTop = chat.scrollHeight
                                })
                        }

                        function chatKeyPress() {
                            const textarea = document.querySelector('#chat-body')
                            if (window.event.keyCode === 13) {
                                const message = textarea.value
                                if (!message) return
                                sendMessage(message)
                                textarea.value = ""
                            }
                        }
                    </script>
                    <input type="text" id="chat-body" class="textarea chat-input" placeholder="Type your message..." onkeypress="chatKeyPress()" style="min-height: 4em;">
                </div>
            </div>
            <button class="modal-close is-large" aria-label="close" onclick="(() => { document.querySelector('.modal').classList.remove('is-active') })()">Close</button>
        </div>
    `))
})

const cringeLord = User.findOrCreate(crypto.randomUUID(), "cringelord", "cringelord")

const urlRegex = /(https?:\/\/)?((([a-zA-Z0-9]+)+(\.[a-zA-Z0-9]+)+)|(localhost))(:\d+)?(\/.*)?/g

app.get('/chat', (req, res) => {
    const user = isSessionValid(req)
    if (!user) {
        res.status(403)
        res.send({ error: 'Access forbidden' })
        return
    }

    const { msg } = req.query
    if (msg) {
        const matches = msg.match(urlRegex)
        if (matches) {
            res.send(`"Sure! I will check out the link${matches.length ? 's' : ''} you provided!"`)
            matches.forEach(link => {
                try {
                    const url = new URL(link.startsWith("http") ? link : `http://${link}`)
                    // avoid fetch recursion
                    if (url.hostname === req.hostname && url.pathname !== '/chat') {
                        console.log("> FETCH " + url)
                        return fetch(url, {
                            headers: {
                                'Cookie': `session=${createSession(cringeLord.id, 10).value}`
                            }
                        }).catch(console.error)
                    }
                    return
                } catch (error) {
                    console.log(error)
                }
            })
            return
        }
    }

    const normalResponses = ["Cringe", "Based", "🤮", "🤢"]
    const message = normalResponses[Math.floor(Math.random() * normalResponses.length)]

    res.send(`"${message}"`)
})

app.get('/user', (req, res) => {
    const user = isSessionValid(req)
    if (!user) {
        res.redirect('/')
        return
    }

    if (!user.balance || user.balance < 1337) {
        res.send(html(`
            <div class="container">
                <section class="section">
                    <div class="section">
                        <div class="section">
                            <p class="is-size-4">Sorry, you need at least 1337 credits to access User Customization ™️</p>
                            <p class="is-size-6">Just stop being poor /s 😢</p>
                        </div>
                        <div class="section">
                            <a class="button is-primary" href="/">Back to dashboard</a>
                        </div>
                    <div>
                </section>
            </div>
        `))
        return
    }

    const sensitiveAttributes = ["id", "credentials", "balance", "role"]

    const { data } = req.query
    if (data) {
        try {
            const changes = JSON.parse(data)
            if (typeof changes !== "object") {
                throw new Error("changes is not an object: " + changes)
            }
            Object.entries(changes).forEach(([key, value]) => {
                if (key in user && !sensitiveAttributes.includes(key)) {
                    user[key] = value
                }
            })
        } catch (error) {
            console.log(error)
        }
    }

    const userAttributes = structuredClone(user)
    sensitiveAttributes.forEach(attr => {
        delete userAttributes[attr]
    })

    res.send(html(`
        <div class="container">
            <section class="section">
                <div class="section>
                    <div class="section">
                        <h1 class="is-size-3">User exclusive area</h1>
                    </div>
                    <div class="section">
                        <a class="button is-primary" href="/flag">Get my flag!</a>
                    </div>
                    <div class="section">
                        <h1 class="is-size-4">Edit my profile</h1>

                        <form>
                            <script>
                                function updateSubmit() {
                                    const submit = document.querySelector('#submit')
                                    const data = Object.fromEntries(Array.from(document.querySelectorAll('input[type=text]')).map(e => [e.name, e.value]))
                                    submit.href = "/user?data=" + JSON.stringify(data)
                                }
                            </script>
                            ${Object.entries(userAttributes).map(([key, value]) => `
                                <div class="field has-addons">
                                    <div class="control">
                                        <a class="button is-info is-static">
                                            ${key}
                                        </a>
                                    </div>
                                    <div class="control">
                                        <input class="input" type="text" name="${key}" value="${value}" onchange="updateSubmit()">
                                    </div>
                                </div>
                            `).join('')}
                            <div class="field">
                                <div class="control">
                                    <a href="#" id="submit" class="button is-primary">Submit changes</a>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="section">
                        <a class="button is-primary" href="/">Back to dashboard</a>
                    </div>
                </div>
            </section>
        </div>
    `))
})

app.get('/flag', (req, res) => {
    const user = isSessionValid(req)
    if (!user) {
        res.redirect('/')
        return
    }

    if (!user.isAdmin) {
        res.send(html(`
            <div class="container">
                <section class="section">
                    <div class="section">
                        <div class="section">
                            <p class="is-size-4">Sorry, only admins can see the flag</p>
                            <p class="is-size-6">What's the proper standard boolean naming anyway? 🤔</p>
                        </div>
                        <div class="section">
                            <a class="button is-primary" href="/user">Back to user profile</a>
                        </div>
                    <div>
                </section>
            </div>
        `))
        return
    }

    function decryptText(encryptedText, secretKey) {
        const decipher = crypto.createDecipher('aes-256-cbc', secretKey);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    res.send(html(`
        <div class="container">
            <section class="section">
                <div class="section">
                    <div class="section">
                        <p class="is-size-4">Congratulations! You found the flag!</p>
                        <p class="is-size-6">🎉The flag is "${decryptText(process.env.ENCRYPTED_FLAG, process.env.ENCRYPTION_KEY)}"🎉</p>
                    </div>
                    <div class="section">
                        <a class="button is-primary" href="/">Back to dashboard</a>
                    </div>
                <div>
            </section>
        </div>
    `))
})

app.get('/credit', (req, res) => {
    const user = isSessionValid(req)
    if (!user) {
        res.redirect('/')
        return
    }

    const { add, to } = req.query
    if (add && to) {
        if (user.role !== "cringelord") {
            res.send(html(`
                <div class="container">
                    <section class="section">
                        <div class="section">
                            <div class="section">
                                <p class="is-size-4">Sorry, only the cringelord is allowed to credit accounts</p>
                            </div>
                            <div class="section">
                                <a class="button is-primary" href="/credit">Back to credit</a>
                            </div>
                        <div>
                    </section>
                </div>
            `))
            return
        }

        const recipient = User.find(to)
        if (!recipient) {
            res.send(html(`
                <div class="container">
                    <section class="section">
                        <div class="section">
                            <div class="section">
                                <p class="is-size-4">Sorry, the target account was not found</p>
                            </div>
                            <div class="section">
                                <a class="button is-primary" href="/">Back to dashboard</a>
                            </div>
                        <div>
                    </section>
                </div>
            `))
            return
        }

        try {
            const amount = parseInt(add)
            if (amount && typeof amount === "number" && !isNaN(amount)) {
                recipient.balance += amount
                res.send(html(`
                    <div class="container">
                        <section class="section">
                            <div class="section">
                                <div class="section">
                                    <p class="is-size-4">Your new balance is ${user.balance}</p>
                                </div>
                                <div class="section">
                                    <a class="button is-primary" href="/">Back to dashboard</a>
                                </div>
                            <div>
                        </section>
                    </div>
                `))
                return
            }
        } catch (error) {
            console.error(error)
        }
    }

    res.send(html(`
        <div class="container">
            <section class="section">
                <div class="section">
                    <div class="section">
                        <form>
                            <div class="field">
                                <label class="label">Amount</label>
                                <div class="control">
                                    <input class="input" type="number" name="add" placeholder="42">
                                    <input type="hidden" name="to" value="${user.id}">
                                </div>
                            </div>
                            <div class="field">
                                <div class="control">
                                    <button class="button is-primary">Add credit</button>
                                </div>
                            </div>
                        </form>
                    </div>
                    <div class="section">
                        <a class="button is-primary" href="/">Back to dashboard</a>
                    </div>
                <div>
            </section>
        </div>
    `))
})

app.get('/login', (req, res) => {
    const user = isSessionValid(req)
    if (user) {
        res.redirect('/')
        return
    }

    const { name = "", credentials, token } = req.query
    let { error } = req.query

    const authenticate = () => {
        if (!name) {
            return false
        }
        try {
            const { type, value } = JSON.parse(credentials)
            const user = User.find(name)
            if (!user) {
                error = "User not found"
                return false
            }
            if (!type || value === undefined) {
                error = "Invalid credentials"
                return false
            }
            if (token && !user.credentials.token) {
                error = "Token-based authentication is not set for this user"
                return false
            }
            if (user.credentials[type] !== sha256(value, 200)) {
                error = "Invalid password"
                return false
            }
            return true
        } catch (exception) {
            error = "Invalid credentials"
            return false
        }
    }

    if (authenticate()) {
        const cookie = createSession(name)
        res.cookie(cookie.name, cookie.value, cookie.options)
        res.redirect('/')
        return
    }

    res.send(html(`
        <style>
            body {
                background: #efefef
            }
            .centered-form {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
        </style>
        <div class="centered-form">
            <div class="box">
                <h1 class="title">Login</h1>
                ` + (error ? `
                <article class="message is-danger">
                    <div class="message-body">
                        ${error}
                    </div>
                </article>`.trim() : "") + `
                <form>
                    <div class="field">
                        <label class="label">Username</label>
                        <div class="control">
                            <input class="input" type="text" name="name" placeholder="Enter your username" value="${name}">
                        </div>
                    </div>
                    <div class="field">
                        <label class="label">${token ? "Token" : "Password"}</label>
                        <div class="control">
                            <script>
                                function updateCredentials() {
                                    const password = document.querySelector('input[type=password]').value
                                    const json = JSON.stringify({ type: ${token ? `"token"` : `"password"`}, value: password })
                                    document.querySelector('input[name=credentials]').value = json
                                }
                            </script>
                            <input class="input" type="password" placeholder="Enter your ${token ? "token" : "password"}" onchange="updateCredentials()">
                            <input type="hidden" name="credentials">
                            ${token ? `<input type="hidden" name="token" value="true">` : ""}
                        </div>
                    </div>
                    <div class="field">
                        <a href="/login${token ? "" : "?token=true"}">Login with a ${token ? "password" : "token"} instead</a>
                    </div>
                    <div class="field">
                        <div class="control">
                            <button class="button is-primary">Login</button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    `).trim())
})

app.get("/create", (req, res) => {
    const { secret, name } = req.query
    if (!secret) {
        res.redirect('/')
    }
    const hash = sha256(secret, 200)
    if (hash === process.env.ADMIN_HASH) {
        const uuid = crypto.randomUUID()
        const user = User.findOrCreate(uuid, name)
        persistUser(user)
        res.send(html(`<pre>${JSON.stringify(user)}</pre>`))
    }
})

app.get("/status", (req, res) => {
    res.send({ status: 'ok' })
})

app.use('/bulma', express.static(path.join(__dirname, 'node_modules', 'bulma', 'css')))

const server = app.listen(8000, () => {
    console.log("Server started")
})

process.once('SIGINT', () => {
    console.log('SIGINT received...');
    server.close();
});

process.once('SIGTERM', () => {
    console.log('SIGTERM received...');
    server.close();
});
const express = require('express');
const app = express();

app.use(express.json());

const delay = () => {
    const min = 100;
    const max = 1000;
    return Math.floor(Math.random() * (max - min + 1)) + min;
};

app.get('/', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "user-service",
            message: "API de Usuários funcionando!",
            endpoint: "/",
            status: "ok"
        });
    }, delay());
});

app.get('/users', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "user-service",
            message: "Lista de usuários",
            users: [
                { id: 1, name: "João" },
                { id: 2, name: "Maria" }
            ],
            status: "ok"
        });
    }, delay());
});

app.get('/users/:id', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "user-service",
            message: "Usuário encontrado",
            user: {
                id: parseInt(req.params.id),
                name: "João",
                email: "joao@email.com"
            },
            status: "ok"
        });
    }, delay());
});

app.post('/users', (req, res) => {
    setTimeout(() => {
        res.status(201).json({
            service: "user-service",
            message: "Usuário criado",
            user: req.body,
            status: "created"
        });
    }, delay());
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`User service running on port ${PORT}`);
});


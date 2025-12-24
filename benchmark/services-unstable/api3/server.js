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
            service: "order-service",
            message: "API de Pedidos funcionando!",
            endpoint: "/",
            status: "ok"
        });
    }, delay());
});

app.get('/orders', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "order-service",
            message: "Lista de pedidos",
            orders: [
                { id: 1, userId: 1, total: 2550.00, status: "completed" },
                { id: 2, userId: 2, total: 100.00, status: "pending" }
            ],
            status: "ok"
        });
    }, delay());
});

app.get('/orders/:id', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "order-service",
            message: "Pedido encontrado",
            order: {
                id: parseInt(req.params.id),
                userId: 1,
                total: 2550.00,
                status: "completed",
                items: ["Notebook", "Mouse"]
            },
            status: "ok"
        });
    }, delay());
});

app.post('/orders', (req, res) => {
    setTimeout(() => {
        res.status(201).json({
            service: "order-service",
            message: "Pedido criado",
            order: req.body,
            status: "created"
        });
    }, delay());
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Order service running on port ${PORT}`);
});


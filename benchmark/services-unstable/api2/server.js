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
            service: "product-service",
            message: "API de Produtos funcionando!",
            endpoint: "/",
            status: "ok"
        });
    }, delay());
});

app.get('/products', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "product-service",
            message: "Lista de produtos",
            products: [
                { id: 1, name: "Notebook", price: 2500.00 },
                { id: 2, name: "Mouse", price: 50.00 }
            ],
            status: "ok"
        });
    }, delay());
});

app.get('/products/:id', (req, res) => {
    setTimeout(() => {
        res.json({
            service: "product-service",
            message: "Produto encontrado",
            product: {
                id: parseInt(req.params.id),
                name: "Notebook",
                price: 2500.00,
                description: "Notebook gamer"
            },
            status: "ok"
        });
    }, delay());
});

app.post('/products', (req, res) => {
    setTimeout(() => {
        res.status(201).json({
            service: "product-service",
            message: "Produto criado",
            product: req.body,
            status: "created"
        });
    }, delay());
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Product service running on port ${PORT}`);
});


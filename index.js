let express = require('express');
const cors = require('cors');
const app = express()
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
    res.status(200).json({ message: "Welcome to the Express API!" });
});

module.exports = app;




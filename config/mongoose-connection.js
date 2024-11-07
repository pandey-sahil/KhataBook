const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_DB_URI).then(() => {
        console.log('Connected to Database');
    });

const db = mongoose.connection;



module.exports = db;
  



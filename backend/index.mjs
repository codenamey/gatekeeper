import mysql from 'mysql2/promise';
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { exec } from 'child_process';

let env = process.env;

// Create a connection to the database
const connection = await mysql.createConnection({
    host: env.DBHOST,
    user: env.DBUSER,
    password: env.DBPASSWORD,
    database: env.DBDATABASE
});

const generateToken = (email, ipaddress) => {
    const payload = {
        email: email,
        ipaddress: ipaddress
    };
    
    const generatedToken = jwt.sign(
        payload,
        env.jwtSecret,
        { expiresIn: '24H' }
    );
    return generatedToken; 
}

const checkEmailAccess = async (email) => {
    try {
        const [results] = await connection.execute(
            `SELECT * FROM mail_user WHERE email = ?`,
            [email]
        );

        if (results.length === 0) {
            return "not allowed";
        } else {
            return "EMAIL:" + results[0].email;
        }
    } catch (error) {
        return "error: " + error.message;
    }
}

const app = express();
const port = 3000;

const getOptions = (bearer, type, customer) => {
    let options;
    if(type.includes('get')) {
        options = {
            method: 'GET',
            headers: {
                'Authorization': bearer,
                'Content-Type': 'application/json'
            }
        };
    } else {
        options = {
            method: 'POST',
            headers: {
                'Authorization': bearer,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(customer)
        };
    }
    return options;
};

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.post('/test', async (req, res) => {
    const body = req.body;
    console.log({body});
    res.send('OK');
});
app.post('/getallallowedipaddresses', async (req, res) => {
    res.send(allowedipaddress);
});

app.post('/verifytoken', async (req, res) => {
    const {email, token} = req.body;
    jwt.verify(token, env.jwtSecret, (err, decoded) => {
        if (err) {
            console.log(err);
            res.send('token is not valid');
        } else {
            console.log(decoded);
            const ip = decoded.ipaddress.split(':').pop(); 
            console.log({ip});
            addIPAddress(ip, decoded.email);
            res.send('token is valid');
        }
    });
});

app.post('/grantaccesstoken', async (req, res) => {
    const remoteip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const body = req.body;
    const {email, url} = body;
    const result = await checkEmailAccess(email);
    if(result.includes('not allowed')){
        res.send("email is not allowed");
    } else {
        const token = generateToken(email, remoteip);
        console.log({token});
        res.send(result);
    }
});

const allowedipaddress = [];
const allowedports = env.allowedports.split(',');

const addIPAddress = (ip, email) => {
    const timestamp = new Date();
    const existingEntry = allowedipaddress.find(entry => entry.ip === ip && entry.email === email);
    if (existingEntry) {
        existingEntry.timestamp = timestamp;
        console.log(`Updated timestamp for IP address ${ip} with email ${email} at ${timestamp}`);
    } else {
        const emailEntries = allowedipaddress.filter(entry => entry.email === email);
        if (emailEntries.length >= 3) {
            // Find the oldest entry and remove it
            emailEntries.sort((a, b) => a.timestamp - b.timestamp);
            const oldestEntry = emailEntries[0];
            allowedipaddress.splice(allowedipaddress.indexOf(oldestEntry), 1);

            // Remove the IP address from iptables for each allowed port
            allowedports.forEach(port => {
                exec(`sudo iptables -D INPUT -s ${oldestEntry.ip} -p tcp --dport ${port} -j ACCEPT`, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`Error removing IP address from iptables: ${error.message}`);
                        return;
                    }
                    if (stderr) {
                        console.error(`iptables stderr: ${stderr}`);
                        return;
                    }
                    console.log(`Removed oldest IP address ${oldestEntry.ip} for email ${email} from iptables port ${port}`);
                });
            });
        }

        allowedipaddress.push({ ip, email, timestamp });
        console.log(`Added IP address ${ip} with email ${email} at ${timestamp}`);

        // Add the IP address to iptables for each allowed port
        allowedports.forEach(port => {
            exec(`sudo iptables -I INPUT -s ${ip} -p tcp --dport ${port} -j ACCEPT`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Error adding IP address to iptables: ${error.message}`);
                    return;
                }
                if (stderr) {
                    console.error(`iptables stderr: ${stderr}`);
                    return;
                }
                console.log(`Added IP address ${ip} for email ${email} to iptables port ${port}`);
            });
        });
    }
};

const removeExpiredIPAddresses = () => {
    const now = new Date();
    allowedipaddress.forEach((entry, index) => {
        const timeDiff = (now - new Date(entry.timestamp)) / 1000 / 60; // Difference in minutes
        if (timeDiff > 60) { // If more than 1 hour
            console.log(`Removing expired IP address ${entry.ip} for email ${entry.email}`);

            // Remove the IP address from iptables for each allowed port
            allowedports.forEach(port => {
                exec(`sudo iptables -D INPUT -s ${entry.ip} -p tcp --dport ${port} -j ACCEPT`, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`Error removing IP address from iptables: ${error.message}`);
                        return;
                    }
                    if (stderr) {
                        console.error(`iptables stderr: ${stderr}`);
                        return;
                    }
                    console.log(`Removed IP address ${entry.ip} for email ${entry.email} from iptables port ${port}`);
                });
            });

            allowedipaddress.splice(index, 1);
        }
    });
};

// Check and remove expired IP addresses every minute
setInterval(removeExpiredIPAddresses, 60 * 1000);

const server = app.listen(port, () => console.log(`Server is running: ${port}!`));
console.log('Server started with variables:');
console.log({env});
console.log('process.env.emailbearer', process.env.emailbearer);
export default server;
